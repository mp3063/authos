<?php

namespace Tests\Feature\Filament;

use App\Events\MfaEnabledEvent;
use App\Filament\Pages\Auth\Login;
use App\Filament\Pages\Auth\Register;
use App\Filament\Resources\UserResource;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Services\Auth\MfaCodeVerifier;
use Filament\Auth\MultiFactor\Pages\SetUpRequiredMultiFactorAuthentication;
use Filament\Auth\Pages\EditProfile;
use Filament\Facades\Filament;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;
use Livewire\Features\SupportTesting\Testable;
use Livewire\Livewire;
use Livewire\Mechanisms\HandleRequests\HandleRequests;
use PHPUnit\Framework\Attributes\Test;
use PragmaRX\Google2FA\Google2FA;
use Spatie\Permission\PermissionRegistrar;
use stdClass;
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
        Event::fake([MfaEnabledEvent::class]);

        [$secret, $recoveryCodes, $setUp] = $this->completeAppAuthenticationSetUp(SetUpRequiredMultiFactorAuthentication::class);

        $setUp->assertRedirect(Filament::getLoginUrl());
        $this->assertGuest();
        Event::assertDispatched(MfaEnabledEvent::class, fn (MfaEnabledEvent $event): bool => $event->user->is($user));
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_enabled']);
        $user->refresh();
        $this->assertSame(['totp'], $user->mfa_methods);
        $this->assertSame($secret, decrypt($user->two_factor_secret));
        $this->assertNotNull($user->two_factor_confirmed_at);
        $this->assertSame($recoveryCodes, $user->two_factor_recovery_codes);
        $this->assertTrue(app(MfaCodeVerifier::class)->verifyTotpCode($user, $this->totpCodeFor($user)));
        $this->assertTrue(app(MfaCodeVerifier::class)->verifyAndConsumeRecoveryCode($user, $recoveryCodes[0]));
        $this->get('/admin')->assertRedirect(Filament::getLoginUrl());
    }

    #[Test]
    public function it_does_not_report_mfa_enabled_or_sign_out_when_the_set_up_action_saves_nothing(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);
        $user = $this->panelUser($organization);
        $this->actingAs($user);
        Event::fake([MfaEnabledEvent::class]);
        $setUp = Livewire::test(SetUpRequiredMultiFactorAuthentication::class)
            ->call('mountAction', 'setUpAppAuthentication', [], ['schemaComponent' => 'content.app']);
        $encrypted = decrypt($setUp->get('mountedActions.0.arguments.encrypted'));

        $setUp->set('mountedActions.0.arguments.encrypted', encrypt([...$encrypted, 'userKey' => 'someone-else']))
            ->set('mountedActions.0.data.code', (new Google2FA)->getCurrentOtp($encrypted['secret']))
            ->set('mountedActions.0.data.password', 'password')
            ->call('callMountedAction')
            ->assertNoRedirect();

        $this->assertAuthenticatedAs($user);
        $this->assertFalse($user->fresh()->hasMfaEnabled());
        Event::assertNotDispatched(MfaEnabledEvent::class);
        $this->assertDatabaseMissing('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_enabled']);
    }

    #[Test]
    public function it_keeps_a_user_who_enrolls_voluntarily_signed_in(): void
    {
        $user = $this->panelUser(Organization::factory()->create());
        $this->actingAs($user);
        Event::fake([MfaEnabledEvent::class]);

        [, , $profile] = $this->completeAppAuthenticationSetUp(EditProfile::class);

        $profile->assertNoRedirect();
        $this->assertAuthenticatedAs($user);
        $this->assertTrue($user->fresh()->hasMfaEnabled());
        Event::assertDispatched(MfaEnabledEvent::class);
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_enabled']);
        $this->get('/admin')->assertOk();
    }

    #[Test]
    public function it_fails_the_panel_challenge_for_a_user_whose_mfa_has_no_secret(): void
    {
        $user = $this->panelUser(Organization::factory()->create());
        $user->forceFill(['mfa_methods' => ['totp'], 'two_factor_secret' => null])->save();

        $this->submitLogin($user)
            ->set('data.multiFactor.app.code', '123456')
            ->call('authenticate')
            ->assertHasErrors();

        $this->assertGuest();
    }

    #[Test]
    public function it_blocks_livewire_updates_once_the_organization_requires_mfa(): void
    {
        $organization = Organization::factory()->create();
        $user = $this->panelUser($organization);
        $this->actingAs($user);
        $html = $this->get(UserResource::getUrl('index'))->assertOk()->getContent();
        preg_match('/wire:snapshot="([^"]+)"/', $html, $matches);
        $snapshot = htmlspecialchars_decode($matches[1], ENT_QUOTES);

        $organization->update(['settings' => ['require_mfa' => true]]);
        $this->actingAs($user->fresh());

        $this->withHeaders(['X-Livewire' => '1'])
            ->postJson(app(HandleRequests::class)->getUpdateUri(), [
                'components' => [['snapshot' => $snapshot, 'updates' => new stdClass, 'calls' => []]],
            ])
            ->assertRedirect(route('filament.admin.auth.multi-factor-authentication.set-up-required'));
    }

    #[Test]
    public function it_keeps_a_member_who_must_set_up_mfa_from_oauth_authorize_until_enrolled_and_signed_in_with_totp(): void
    {
        $organization = Organization::factory()->create();
        $user = $this->panelUser($organization);
        $application = Application::factory()->create();
        $authorizeUrl = $this->authorizeUrl($application);
        $setUpUrl = route('filament.admin.auth.multi-factor-authentication.set-up-required');
        $this->submitLogin($user)->assertHasNoErrors();
        $authToken = $this->authTokenFrom($this->get($authorizeUrl)->assertOk()->getContent());

        $organization->update(['settings' => ['require_mfa' => true]]);
        $this->actingAs($user->fresh());

        $this->get($authorizeUrl)->assertRedirect($setUpUrl);
        $this->assertSame($authorizeUrl, session('url.intended'));
        $this->approve($application, $authToken)->assertRedirect($setUpUrl);
        $this->assertDatabaseCount('oauth_auth_codes', 0);

        $this->completeAppAuthenticationSetUp(SetUpRequiredMultiFactorAuthentication::class);
        $this->assertGuest();
        $this->assertSame($authorizeUrl, session('url.intended'));

        $user->refresh();
        $login = $this->submitLogin($user);
        $this->assertGuest();
        $login->set('data.multiFactor.app.code', $this->totpCodeFor($user))
            ->call('authenticate')
            ->assertRedirect($authorizeUrl);
        $this->assertAuthenticatedAs($user);
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
        $application = Application::factory()->create();
        $this->get($this->authorizeUrl($application))->assertRedirect($setUpUrl);
        $this->approve($application, 'any-token')->assertRedirect($setUpUrl);
        $this->assertDatabaseCount('oauth_auth_codes', 0);

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
        $authorizeUrl = $this->authorizeUrl($application);

        $this->get($authorizeUrl)->assertRedirect(route('filament.admin.auth.login'));

        $login = $this->submitLogin($user);
        $this->assertGuest();

        $login->set('data.multiFactor.app.code', $this->totpCodeFor($user))
            ->call('authenticate')
            ->assertRedirect($authorizeUrl);
        $this->assertAuthenticatedAs($user);

        $this->get($authorizeUrl)->assertOk()->assertSee('name="auth_token"', false);
    }

    private function authorizeUrl(Application $application): string
    {
        return url('/oauth/authorize?'.http_build_query([
            'client_id' => $application->passport_client_id,
            'redirect_uri' => $application->redirect_uris[0],
            'response_type' => 'code',
            'scope' => '',
            'state' => 'abc123',
        ]));
    }

    private function authTokenFrom(string $html): string
    {
        preg_match('/name="auth_token" value="([^"]+)"/', $html, $matches);

        return $matches[1];
    }

    private function approve(Application $application, string $authToken): TestResponse
    {
        return $this->post('/oauth/authorize', [
            'state' => 'abc123',
            'client_id' => $application->passport_client_id,
            'auth_token' => $authToken,
        ]);
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
     * @param  class-string  $page
     * @return array{0: string, 1: array<string>, 2: Testable}
     */
    private function completeAppAuthenticationSetUp(string $page): array
    {
        $setUp = Livewire::test($page)
            ->call('mountAction', 'setUpAppAuthentication', [], ['schemaComponent' => 'content.app']);
        $encrypted = decrypt($setUp->get('mountedActions.0.arguments.encrypted'));

        $setUp->set('mountedActions.0.data.code', (new Google2FA)->getCurrentOtp($encrypted['secret']))
            ->set('mountedActions.0.data.password', 'password')
            ->call('callMountedAction')
            ->assertHasNoErrors();

        return [$encrypted['secret'], $encrypted['recoveryCodes'], $setUp];
    }
}
