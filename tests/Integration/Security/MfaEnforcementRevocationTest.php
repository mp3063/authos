<?php

namespace Tests\Integration\Security;

use App\Filament\Resources\UserResource\Pages\ViewUser;
use App\Jobs\RevokeCredentialsForOrganizationMfaJob;
use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\Token;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class MfaEnforcementRevocationTest extends IntegrationTestCase
{
    private Client $passwordClient;

    protected function setUp(): void
    {
        parent::setUp();

        $this->passwordClient = Client::create([
            'name' => 'Password Grant Client',
            'secret' => 'password-client-secret',
            'redirect' => '',
            'personal_access_client' => false,
            'password_client' => true,
            'revoked' => false,
        ]);
    }

    private function organization(mixed $requireMfa): Organization
    {
        $organization = Organization::factory()->create();
        $organization->update(['settings' => array_merge($organization->settings ?? [], ['require_mfa' => $requireMfa])]);

        return $organization->fresh();
    }

    private function setRequireMfa(Organization $organization, mixed $requireMfa): void
    {
        $organization->update(['settings' => array_merge($organization->settings ?? [], ['require_mfa' => $requireMfa])]);
    }

    private function memberOf(Organization $organization): User
    {
        return User::factory()->forOrganization($organization)->create([
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
            'is_active' => true,
        ]);
    }

    private function enrollInMfa(User $user): void
    {
        $user->update(['mfa_methods' => ['totp'], 'two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'), 'two_factor_confirmed_at' => now()]);
    }

    /**
     * @return array{refresh_token: string, personal: Token, session: SSOSession}
     */
    private function credentialsFor(User $user): array
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => $user->email,
            'password' => 'password123',
            'scope' => '',
        ]);
        $response->assertOk();

        return [
            'refresh_token' => $response->json('refresh_token'),
            'personal' => $user->createToken('personal')->token,
            'session' => SSOSession::factory()->create(['user_id' => $user->id]),
        ];
    }

    private function refreshWith(string $refreshToken): TestResponse
    {
        return $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'refresh_token' => $refreshToken,
            'scope' => '',
        ]);
    }

    private function assertRevoked(User $user, array $credentials): void
    {
        $this->assertSame(0, DB::table('oauth_access_tokens')->where('user_id', $user->id)->where('revoked', false)->count());
        $this->assertTrue($credentials['personal']->fresh()->revoked);
        $this->assertNotNull($credentials['session']->fresh()->logged_out_at);
        $this->refreshWith($credentials['refresh_token'])->assertStatus(400)->assertJson(['error' => 'invalid_grant']);
    }

    private function assertKept(User $user, array $credentials): void
    {
        $this->assertSame(2, DB::table('oauth_access_tokens')->where('user_id', $user->id)->where('revoked', false)->count());
        $this->assertFalse($credentials['personal']->fresh()->revoked);
        $this->assertNull($credentials['session']->fresh()->logged_out_at);
        $this->refreshWith($credentials['refresh_token'])->assertOk();
    }

    #[Test]
    public function it_revokes_member_credentials_when_an_organization_starts_requiring_mfa(): void
    {
        $organization = $this->organization(false);
        $member = $this->memberOf($organization);
        $memberCredentials = $this->credentialsFor($member);
        $enrolled = $this->memberOf($organization);
        $enrolledCredentials = $this->credentialsFor($enrolled);
        $this->enrollInMfa($enrolled);
        $outsider = $this->memberOf($this->organization(false));
        $outsiderCredentials = $this->credentialsFor($outsider);

        $this->setRequireMfa($organization, true);

        $this->assertRevoked($member, $memberCredentials);
        $this->assertKept($enrolled, $enrolledCredentials);
        $this->assertKept($outsider, $outsiderCredentials);
    }

    #[Test]
    public function it_does_nothing_when_require_mfa_is_saved_unchanged_or_switched_off(): void
    {
        $required = $this->organization(true);
        $member = $this->memberOf($required);
        $personal = $member->createToken('personal')->token;
        $session = SSOSession::factory()->create(['user_id' => $member->id]);
        $open = $this->organization(false);
        $openMember = $this->memberOf($open);
        $openCredentials = $this->credentialsFor($openMember);

        $required->update(['settings' => array_merge($required->settings, ['session_timeout' => 30])]);
        $this->setRequireMfa($required, 'true');
        $this->setRequireMfa($open, false);
        $open->update(['settings' => array_merge($open->settings, ['session_timeout' => 30])]);
        $this->setRequireMfa($required, false);

        $this->assertFalse($personal->fresh()->revoked);
        $this->assertNull($session->fresh()->logged_out_at);
        $this->assertKept($openMember, $openCredentials);
    }

    #[Test]
    public function it_treats_a_stringy_require_mfa_as_on(): void
    {
        $organization = $this->organization(false);
        $member = $this->memberOf($organization);
        $credentials = $this->credentialsFor($member);

        $this->setRequireMfa($organization, '1');

        $this->assertRevoked($member, $credentials);
    }

    #[Test]
    public function it_revokes_credentials_when_a_user_moves_into_an_organization_requiring_mfa(): void
    {
        $open = $this->organization(false);
        $required = $this->organization(true);
        $mover = $this->memberOf($open);
        $moverCredentials = $this->credentialsFor($mover);
        $enrolledMover = $this->memberOf($open);
        $enrolledCredentials = $this->credentialsFor($enrolledMover);
        $this->enrollInMfa($enrolledMover);
        $stayer = $this->memberOf($open);
        $stayerCredentials = $this->credentialsFor($stayer);
        $mover->load('organization');

        $mover->update(['organization_id' => $required->id]);
        $enrolledMover->update(['organization_id' => $required->id]);

        $this->assertRevoked($mover, $moverCredentials);
        $this->assertKept($enrolledMover, $enrolledCredentials);
        $this->assertKept($stayer, $stayerCredentials);
    }

    #[Test]
    public function it_leaves_credentials_when_a_user_moves_into_an_organization_not_requiring_mfa(): void
    {
        $user = $this->memberOf($this->organization(false));
        $credentials = $this->credentialsFor($user);

        $user->update(['organization_id' => $this->organization(false)->id]);

        $this->assertKept($user, $credentials);
    }

    #[Test]
    public function it_dispatches_the_organization_job_only_when_require_mfa_turns_on(): void
    {
        Bus::fake([RevokeCredentialsForOrganizationMfaJob::class]);
        $organization = $this->organization(false);
        $organization->update(['settings' => array_merge($organization->settings, ['session_timeout' => 30])]);

        $this->setRequireMfa($organization, true);
        $this->setRequireMfa($organization, true);
        $organization->update(['settings' => array_merge($organization->settings, ['session_timeout' => 60])]);
        $this->setRequireMfa($organization, false);
        $organization->update(['settings' => array_merge($organization->settings, ['session_timeout' => 90])]);

        Bus::assertDispatchedTimes(RevokeCredentialsForOrganizationMfaJob::class, 1);
        Bus::assertDispatched(RevokeCredentialsForOrganizationMfaJob::class, fn ($job) => $job->organization->is($organization));
    }

    #[Test]
    public function it_revokes_credentials_when_an_admin_resets_mfa_for_a_member_of_an_organization_requiring_mfa(): void
    {
        $organization = $this->organization(false);
        $member = $this->memberOf($organization);
        $credentials = $this->credentialsFor($member);
        $this->enrollInMfa($member);
        $this->setRequireMfa($organization, true);
        $admin = $this->createUser(['organization_id' => $organization->id, 'mfa_methods' => ['totp']], 'Organization Owner');
        $this->assertFalse($credentials['personal']->fresh()->revoked);
        $this->actingAs($admin);

        Livewire::test(ViewUser::class, ['record' => $member->getRouteKey()])->callAction('reset_mfa');

        $this->assertTrue($member->fresh()->mustSetUpMfa());
        $this->assertRevoked($member, $credentials);
    }

    #[Test]
    public function it_keeps_credentials_when_mfa_fields_change_outside_an_organization_requiring_mfa(): void
    {
        $member = $this->memberOf($this->organization(false));
        $credentials = $this->credentialsFor($member);
        $this->enrollInMfa($member);

        $member->update(['mfa_methods' => null, 'two_factor_secret' => null, 'two_factor_recovery_codes' => null, 'two_factor_confirmed_at' => null]);

        $this->assertKept($member, $credentials);
    }
}
