<?php

namespace Tests\Integration\Security;

use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Client;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class RevokeTokensForMfaSetupCommandTest extends IntegrationTestCase
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

    private function organization(bool $requiresMfa): Organization
    {
        $organization = Organization::factory()->create();
        $organization->update(['settings' => array_merge($organization->settings ?? [], ['require_mfa' => $requiresMfa])]);

        return $organization;
    }

    private function mintPasswordGrantTokens(User $user): array
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

        return $response->json();
    }

    private function refreshWith(string $refreshToken)
    {
        return $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'refresh_token' => $refreshToken,
            'scope' => '',
        ]);
    }

    private function enableRequirement(Organization $organization): void
    {
        $organization->update(['settings' => array_merge($organization->settings ?? [], ['require_mfa' => true])]);
    }

    private function memberOf(Organization $organization): User
    {
        return User::factory()->forOrganization($organization)->create([
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
            'is_active' => true,
        ]);
    }

    #[Test]
    public function it_revokes_access_and_refresh_tokens_of_members_who_must_set_up_mfa(): void
    {
        $organization = $this->organization(false);
        $member = $this->memberOf($organization);
        $tokens = $this->mintPasswordGrantTokens($member);
        $personalToken = $member->createToken('personal')->token;
        $session = SSOSession::factory()->create(['user_id' => $member->id]);
        $this->enableRequirement($organization);
        $this->artisan('auth:revoke-tokens-for-mfa-setup')->assertSuccessful();

        $this->assertSame(0, DB::table('oauth_access_tokens')->where('user_id', $member->id)->where('revoked', false)->count());
        $this->assertSame(0, DB::table('oauth_refresh_tokens')->where('revoked', false)->count());
        $this->assertTrue($personalToken->fresh()->revoked);
        $this->assertNotNull($session->fresh()->logged_out_at);
        $this->refreshWith($tokens['refresh_token'])->assertStatus(400)->assertJson(['error' => 'invalid_grant']);
    }

    #[Test]
    public function it_rejects_a_refresh_token_issued_before_the_organization_required_mfa(): void
    {
        $organization = $this->organization(false);
        $member = $this->memberOf($organization);
        $tokens = $this->mintPasswordGrantTokens($member);
        $this->enableRequirement($organization);

        $this->artisan('auth:revoke-tokens-for-mfa-setup')->assertSuccessful();

        $response = $this->refreshWith($tokens['refresh_token']);
        $response->assertStatus(400)->assertJson(['error' => 'invalid_grant']);
        $this->assertArrayNotHasKey('access_token', $response->json());
    }

    #[Test]
    public function it_leaves_tokens_of_users_who_have_mfa_or_need_none(): void
    {
        $required = $this->organization(false);
        $withMfa = $this->memberOf($required);
        $withMfaTokens = $this->mintPasswordGrantTokens($withMfa);
        $withMfa->update(['mfa_methods' => ['totp'], 'two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'), 'two_factor_confirmed_at' => now()]);
        $withMfaPersonal = $withMfa->createToken('personal')->token;
        $withMfaSession = SSOSession::factory()->create(['user_id' => $withMfa->id]);

        $open = $this->organization(false);
        $needsNone = $this->memberOf($open);
        $needsNoneTokens = $this->mintPasswordGrantTokens($needsNone);
        $needsNonePersonal = $needsNone->createToken('personal')->token;
        $needsNoneSession = SSOSession::factory()->create(['user_id' => $needsNone->id]);

        $this->enableRequirement($required);

        $this->artisan('auth:revoke-tokens-for-mfa-setup')->assertSuccessful();

        $this->assertFalse($withMfaPersonal->fresh()->revoked);
        $this->assertFalse($needsNonePersonal->fresh()->revoked);
        $this->assertNull($withMfaSession->fresh()->logged_out_at);
        $this->assertNull($needsNoneSession->fresh()->logged_out_at);
        $this->refreshWith($withMfaTokens['refresh_token'])->assertOk();
        $this->refreshWith($needsNoneTokens['refresh_token'])->assertOk();
    }

    #[Test]
    public function it_only_reports_in_dry_run(): void
    {
        $organization = $this->organization(false);
        $member = $this->memberOf($organization);
        $tokens = $this->mintPasswordGrantTokens($member);
        $personalToken = $member->createToken('personal')->token;
        $session = SSOSession::factory()->create(['user_id' => $member->id]);
        $this->enableRequirement($organization);

        $this->artisan('auth:revoke-tokens-for-mfa-setup', ['--dry-run' => true])
            ->expectsOutputToContain('Access tokens: 2')
            ->expectsOutputToContain('Refresh tokens: 1')
            ->expectsOutputToContain('SSO sessions: 1')
            ->assertSuccessful();

        $this->assertFalse($personalToken->fresh()->revoked);
        $this->assertNull($session->fresh()->logged_out_at);
        $this->assertSame(0, DB::table('oauth_refresh_tokens')->where('revoked', true)->count());
    }
}
