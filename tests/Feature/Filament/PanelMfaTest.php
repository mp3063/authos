<?php

namespace Tests\Feature\Filament;

use App\Filament\Pages\Auth\Login;
use App\Filament\Pages\Auth\Register;
use App\Filament\Resources\UserResource;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Services\Auth\MfaCodeVerifier;
use Filament\Auth\MultiFactor\Pages\SetUpRequiredMultiFactorAuthentication;
use Filament\Auth\Pages\EditProfile;
use Illuminate\Support\Arr;
use Livewire\Features\SupportTesting\Testable;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use PragmaRX\Google2FA\Google2FA;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class PanelMfaTest extends IntegrationTestCase
{
    #[Test]
    public function it_challenges_a_panel_user_with_mfa_before_logging_in(): void
    {
        $user = $this->panelUser(Organization::factory()->create(), withMfa: true);

        $login = $this->submitLogin($user);

        $this->assertNotNull($login->get('userUndertakingMultiFactorAuthentication'));
        $this->assertGuest();

        $login->set('data.multiFactor.app.code', '000000')->call('authenticate')->assertHasErrors();
        $this->assertGuest();

        $login->set('data.multiFactor.app.code', $this->totpCodeFor($user))
            ->call('authenticate')
            ->assertHasNoErrors()
            ->assertRedirect(url('/admin'));
        $this->assertAuthenticatedAs($user);
    }

    #[Test]
    public function it_accepts_a_recovery_code_at_the_panel_challenge_and_consumes_it(): void
    {
        $user = $this->panelUser(Organization::factory()->create(), withMfa: true);
        $recoveryCode = $user->two_factor_recovery_codes[0];

        $this->submitLogin($user)
            ->set('data.multiFactor.app.useRecoveryCode', true)
            ->set('data.multiFactor.app.recoveryCode', $recoveryCode)
            ->call('authenticate')
            ->assertHasNoErrors();

        $this->assertAuthenticatedAs($user);
        $remainingCodes = $user->fresh()->two_factor_recovery_codes;
        $this->assertCount(7, $remainingCodes);
        $this->assertNotContains($recoveryCode, $remainingCodes);
    }

    #[Test]
    public function it_sends_a_member_of_an_mfa_required_organization_without_mfa_to_set_up_mfa(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);
        $user = $this->panelUser($organization);
        $setUpUrl = route('filament.admin.auth.multi-factor-authentication.set-up-required');

        $this->submitLogin($user)->assertHasNoErrors();

        $this->assertAuthenticatedAs($user);
        foreach (['/admin', UserResource::getUrl('index'), EditProfile::getUrl()] as $panelUrl) {
            $this->get($panelUrl)->assertRedirect($setUpUrl);
        }
        $this->get($setUpUrl)->assertOk();

        [$secret, $recoveryCodes] = $this->completeAppAuthenticationSetUp();

        $user->refresh();
        $this->assertSame(['totp'], $user->mfa_methods);
        $this->assertSame($secret, decrypt($user->two_factor_secret));
        $this->assertNotNull($user->two_factor_confirmed_at);
        $this->assertSame($recoveryCodes, $user->two_factor_recovery_codes);
        $this->assertTrue(app(MfaCodeVerifier::class)->verifyTotpCode($user, $this->totpCodeFor($user)));
        $this->assertTrue(app(MfaCodeVerifier::class)->verifyAndConsumeRecoveryCode($user, $recoveryCodes[0]));
        $this->get('/admin')->assertOk();
    }

    #[Test]
    public function it_lets_a_user_without_any_mfa_requirement_into_the_panel_unchallenged(): void
    {
        $user = $this->panelUser(Organization::factory()->create());

        $login = $this->submitLogin($user)->assertHasNoErrors()->assertRedirect(url('/admin'));

        $this->assertNull($login->get('userUndertakingMultiFactorAuthentication'));
        $this->assertAuthenticatedAs($user);
        $this->get('/admin')->assertOk();
    }

    #[Test]
    public function it_keeps_a_registrant_of_an_mfa_required_organization_out_of_the_panel_until_mfa_is_set_up(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);
        $setUpUrl = route('filament.admin.auth.multi-factor-authentication.set-up-required');

        Livewire::test(Register::class)
            ->fillForm([
                'organization_id' => $organization->id,
                'name' => 'New Member',
                'email' => 'new-member@example.com',
                'password' => 'Str0ng!Passw0rd#2026',
                'passwordConfirmation' => 'Str0ng!Passw0rd#2026',
            ])
            ->call('register')
            ->assertHasNoErrors();

        $registrant = User::where('email', 'new-member@example.com')->sole();
        $this->assertAuthenticatedAs($registrant);
        $this->get('/admin')->assertForbidden();

        $registrant->forceFill(['email_verified_at' => now()])->save();
        $this->setupRoleWithPermissions('Organization Admin', 'web', $organization->id);
        $registrant->assignOrganizationRole('Organization Admin', $organization->id);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        foreach (['/admin', UserResource::getUrl('index'), EditProfile::getUrl()] as $panelUrl) {
            $this->get($panelUrl)->assertRedirect($setUpUrl);
        }
    }

    #[Test]
    public function it_does_not_let_a_member_disable_mfa_while_the_organization_requires_it(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);
        $user = $this->panelUser($organization, withMfa: true);
        $this->actingAs($user);

        Livewire::test(EditProfile::class)
            ->call('mountAction', 'disableAppAuthentication', [], ['schemaComponent' => 'content.app'])
            ->set('mountedActions.0.data.password', 'password')
            ->set('mountedActions.0.data.code', $this->totpCodeFor($user))
            ->call('callMountedAction');

        $this->assertTrue($user->fresh()->hasMfaEnabled());
    }

    #[Test]
    public function it_returns_to_the_oauth_authorize_prompt_after_the_panel_mfa_challenge(): void
    {
        $user = $this->panelUser(Organization::factory()->create(), withMfa: true);
        $application = Application::factory()->create();
        $authorizeUrl = url('/oauth/authorize?'.http_build_query([
            'client_id' => $application->passport_client_id,
            'redirect_uri' => $application->redirect_uris[0],
            'response_type' => 'code',
            'scope' => '',
            'state' => 'abc123',
        ]));

        $this->get($authorizeUrl)->assertRedirect(route('filament.admin.auth.login'));

        $login = $this->submitLogin($user);
        $this->assertGuest();

        $login->set('data.multiFactor.app.code', $this->totpCodeFor($user))
            ->call('authenticate')
            ->assertRedirect($authorizeUrl);
        $this->assertAuthenticatedAs($user);

        $this->get($authorizeUrl)->assertOk()->assertSee('name="auth_token"', false);
    }

    private function panelUser(Organization $organization, bool $withMfa = false): User
    {
        $mfaAttributes = $withMfa
            ? Arr::only(User::factory()->withMfa()->raw(), ['two_factor_secret', 'two_factor_confirmed_at', 'two_factor_recovery_codes', 'mfa_methods'])
            : [];

        $user = $this->createUser(['organization_id' => $organization->id, ...$mfaAttributes], 'Organization Owner');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        return $user->fresh();
    }

    private function submitLogin(User $user): Testable
    {
        return Livewire::test(Login::class)
            ->fillForm(['email' => $user->email, 'password' => 'password'])
            ->call('authenticate');
    }

    /**
     * @return array{0: string, 1: array<string>}
     */
    private function completeAppAuthenticationSetUp(): array
    {
        $setUp = Livewire::test(SetUpRequiredMultiFactorAuthentication::class)
            ->call('mountAction', 'setUpAppAuthentication', [], ['schemaComponent' => 'content.app']);
        $encrypted = decrypt($setUp->get('mountedActions.0.arguments.encrypted'));

        $setUp->set('mountedActions.0.data.code', (new Google2FA)->getCurrentOtp($encrypted['secret']))
            ->set('mountedActions.0.data.password', 'password')
            ->call('callMountedAction')
            ->assertHasNoErrors();

        return [$encrypted['secret'], $encrypted['recoveryCodes']];
    }
}
