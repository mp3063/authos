<?php

namespace Tests\Integration\SSO;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SsoMfaEnforcementTest extends IntegrationTestCase
{
    use SignsSamlResponses;

    private const IDP_ENTITY_ID = 'https://idp.example.com';

    private const SP_ENTITY_ID = 'https://authos.example.com/saml/sp';

    private const OIDC_CALLBACK_URL = 'https://app.example.com/callback';

    #[Test]
    public function it_withholds_the_sso_session_token_from_a_user_who_requires_mfa_on_oidc_callback(): void
    {
        $user = User::factory()->withMfa()->create();
        $configuration = $this->createOidcConfiguration($user);

        $response = $this->completeOidcCallback($user, $configuration);

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonPath('available_methods', ['totp'])
            ->assertJsonMissingPath('session')
            ->assertJsonMissingPath('tokens');
        $this->assertNotEmpty($response->json('challenge_token'));
        $this->assertDatabaseCount('sso_sessions', 0);
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_required']);
    }

    #[Test]
    public function it_issues_the_sso_session_after_mfa_verification_on_oidc_callback(): void
    {
        $user = User::factory()->withMfa()->create();
        $configuration = $this->createOidcConfiguration($user);
        $challengeToken = $this->completeOidcCallback($user, $configuration)->json('challenge_token');

        $response = $this->verifyChallenge($challengeToken, $user);

        $response->assertOk()
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('application.id', $configuration->application_id);
        $this->assertDatabaseCount('sso_sessions', 1);
        $session = SSOSession::firstOrFail();
        $this->assertSame($session->session_token, $response->json('session.session_token'));
        $this->assertSame($user->id, $session->user_id);
        $this->assertTrue($session->isActive());
        $this->assertSame('idp-access-token', $session->metadata['access_token']);
        $this->verifyChallenge($challengeToken, $user)->assertUnauthorized();
        $this->assertDatabaseCount('sso_sessions', 1);
    }

    #[Test]
    public function it_withholds_the_sso_session_token_from_a_user_who_requires_mfa_on_saml_callback(): void
    {
        $user = User::factory()->withMfa()->create();
        $application = $this->createSamlApplication($user);
        $this->createPendingSamlRequest($application);

        $response = $this->postSamlCallback($user);

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonMissingPath('session')
            ->assertJsonMissingPath('tokens');
        $this->assertNotEmpty($response->json('challenge_token'));
        $this->assertDatabaseCount('sso_sessions', 0);
    }

    #[Test]
    public function it_issues_the_sso_session_after_mfa_verification_on_saml_callback(): void
    {
        $user = User::factory()->withMfa()->create();
        $application = $this->createSamlApplication($user);
        $this->createPendingSamlRequest($application);
        $challengeToken = $this->postSamlCallback($user)->json('challenge_token');

        $response = $this->verifyChallenge($challengeToken, $user);

        $response->assertOk()
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('application.id', $application->id);
        $this->assertDatabaseCount('sso_sessions', 1);
        $session = SSOSession::firstOrFail();
        $this->assertSame($user->id, $session->user_id);
        $this->assertSame($session->session_token, $response->json('session.session_token'));
        $this->verifyChallenge($challengeToken, $user)->assertUnauthorized();
        $this->assertDatabaseCount('sso_sessions', 1);
    }

    #[Test]
    public function it_withholds_the_sso_session_token_from_a_user_who_requires_mfa_on_saml_idp_initiated_acs(): void
    {
        $user = User::factory()->withMfa()->create();
        $this->createSamlApplication($user);

        $response = $this->postIdpInitiatedAssertion($user);

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonMissingPath('session')
            ->assertJsonMissingPath('tokens');
        $this->assertNotEmpty($response->json('challenge_token'));
        $this->assertDatabaseCount('sso_sessions', 0);
    }

    #[Test]
    public function it_issues_the_sso_session_after_mfa_verification_on_saml_idp_initiated_acs(): void
    {
        $user = User::factory()->withMfa()->create();
        $application = $this->createSamlApplication($user);
        $challengeToken = $this->postIdpInitiatedAssertion($user)->json('challenge_token');

        $response = $this->verifyChallenge($challengeToken, $user);

        $response->assertOk()
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('application.id', $application->id);
        $this->assertDatabaseCount('sso_sessions', 1);
        $session = SSOSession::firstOrFail();
        $this->assertSame($session->session_token, $response->json('session.session_token'));
        $this->assertSame('idp_initiated', $session->metadata['flow']);
        $this->assertSame($user->email, $session->metadata['name_id']);
        $this->verifyChallenge($challengeToken, $user)->assertUnauthorized();
        $this->assertDatabaseCount('sso_sessions', 1);
    }

    #[Test]
    public function it_refuses_the_sso_session_when_the_configuration_was_deactivated_before_verification(): void
    {
        $user = User::factory()->withMfa()->create();
        $application = $this->createSamlApplication($user);
        $challengeToken = $this->postIdpInitiatedAssertion($user)->json('challenge_token');
        $application->ssoConfiguration->update(['is_active' => false]);

        $response = $this->verifyChallenge($challengeToken, $user);

        $response->assertUnauthorized()->assertJsonMissingPath('session');
        $this->assertDatabaseCount('sso_sessions', 0);
    }

    #[Test]
    public function it_refuses_the_sso_session_when_the_configuration_moved_to_another_organization_before_verification(): void
    {
        $user = User::factory()->withMfa()->create();
        $application = $this->createSamlApplication($user);
        $challengeToken = $this->postIdpInitiatedAssertion($user)->json('challenge_token');
        $application->update(['organization_id' => Organization::factory()->create()->id]);

        $response = $this->verifyChallenge($challengeToken, $user);

        $response->assertUnauthorized()->assertJsonMissingPath('session');
        $this->assertDatabaseCount('sso_sessions', 0);
    }

    #[Test]
    public function it_warns_about_low_recovery_codes_when_a_recovery_code_verifies_the_sso_challenge(): void
    {
        $user = User::factory()->withMfa()->create(['two_factor_recovery_codes' => ['code-one-aaaa', 'code-two-bbbb']]);
        $this->createSamlApplication($user);
        $challengeToken = $this->postIdpInitiatedAssertion($user)->json('challenge_token');

        $response = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken,
            'recovery_code' => 'code-one-aaaa',
        ]);

        $response->assertOk()
            ->assertJsonPath('warning', 'Only 1 recovery codes remaining. Please regenerate new codes.');
        $this->assertNotEmpty($response->json('session.session_token'));
    }

    #[Test]
    public function it_returns_a_setup_token_for_sso_into_an_organization_that_requires_mfa(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);
        $user = User::factory()->forOrganization($organization)->create();
        $this->createSamlApplication($user);

        $response = $this->postIdpInitiatedAssertion($user);

        $response->assertForbidden()
            ->assertJsonPath('error', 'mfa_setup_required')
            ->assertJsonPath('mfa_setup_required', true)
            ->assertJsonPath('token_type', 'Bearer')
            ->assertJsonMissingPath('session');
        $this->assertNotEmpty($response->json('setup_token'));
        $this->assertDatabaseCount('sso_sessions', 0);
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_setup_required']);
    }

    #[Test]
    public function it_issues_the_sso_session_directly_when_no_mfa_is_required(): void
    {
        $user = User::factory()->create();
        $this->createSamlApplication($user);

        $response = $this->postIdpInitiatedAssertion($user);

        $response->assertOk()->assertJsonPath('user.id', $user->id);
        $this->assertDatabaseCount('sso_sessions', 1);
        $session = SSOSession::firstOrFail();
        $this->assertSame($session->session_token, $response->json('session.session_token'));
        $this->assertExpiresAfterLifetime($session, 3600);
    }

    #[Test]
    public function it_issues_a_fresh_sso_session_on_every_idp_initiated_login(): void
    {
        $user = User::factory()->create();
        $application = $this->createSamlApplication($user);
        $earlierSession = SSOSession::factory()->forUser($user)->create([
            'application_id' => $application->id,
            'expires_at' => now()->addMinutes(30),
        ]);

        $response = $this->postIdpInitiatedAssertion($user);

        $response->assertOk();
        $this->assertDatabaseCount('sso_sessions', 2);
        $this->assertNotSame($earlierSession->session_token, $response->json('session.session_token'));
        $this->assertEquals($earlierSession->expires_at, $earlierSession->fresh()->expires_at);
        $this->assertExpiresAfterLifetime(SSOSession::where('session_token', $response->json('session.session_token'))->firstOrFail(), 3600);
    }

    #[Test]
    public function it_issues_the_oidc_session_for_the_configured_lifetime_when_no_mfa_is_required(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user);
        $configuration->update(['session_lifetime' => 300]);

        $response = $this->completeOidcCallback($user, $configuration);

        $response->assertOk();
        $this->assertDatabaseCount('sso_sessions', 1);
        $this->assertExpiresAfterLifetime(SSOSession::firstOrFail(), 300);
    }

    private function assertExpiresAfterLifetime(SSOSession $session, int $lifetimeSeconds): void
    {
        $this->assertTrue(
            $session->expires_at->between(now()->addSeconds($lifetimeSeconds - 10), now()->addSeconds($lifetimeSeconds)),
            "Session expires at {$session->expires_at}, expected about {$lifetimeSeconds}s from now"
        );
    }

    private function createOidcConfiguration(User $user): SSOConfiguration
    {
        $application = Application::factory()->create(['organization_id' => $user->organization_id]);
        $user->applications()->attach($application->id, ['granted_at' => now()]);

        Http::fake([
            'https://idp.example.com/token' => Http::response([
                'access_token' => 'idp-access-token',
                'id_token' => 'idp-id-token',
                'refresh_token' => 'idp-refresh-token',
            ]),
            'https://idp.example.com/userinfo' => Http::response(['sub' => 'idp-user', 'email' => $user->email]),
        ]);

        return SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'provider' => 'oidc',
            'callback_url' => self::OIDC_CALLBACK_URL,
            'allowed_domains' => ['app.example.com'],
            'configuration' => [
                'client_id' => 'client',
                'client_secret' => 'secret',
                'authorization_endpoint' => 'https://idp.example.com/auth',
                'token_endpoint' => 'https://idp.example.com/token',
                'userinfo_endpoint' => 'https://idp.example.com/userinfo',
            ],
            'is_active' => true,
        ]);
    }

    private function completeOidcCallback(User $user, SSOConfiguration $configuration): TestResponse
    {
        Passport::actingAs($user, ['sso']);

        $state = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $configuration->application_id,
            'sso_configuration_id' => $configuration->id,
            'redirect_uri' => self::OIDC_CALLBACK_URL,
        ])->assertOk()->json('state');

        return $this->postJson('/api/v1/sso/callback', ['code' => 'idp-code', 'state' => $state]);
    }

    private function createSamlApplication(User $user): Application
    {
        $application = $this->createOAuthApplication(['organization_id' => $user->organization_id]);

        SSOConfiguration::create([
            'application_id' => $application->id,
            'name' => 'SAML IdP',
            'provider' => 'saml2',
            'callback_url' => 'https://app.example.com/saml/callback',
            'logout_url' => 'https://app.example.com/saml/logout',
            'allowed_domains' => ['example.com'],
            'session_lifetime' => 3600,
            'is_active' => true,
            'configuration' => [
                'idp_entity_id' => self::IDP_ENTITY_ID,
                'sp_entity_id' => self::SP_ENTITY_ID,
                'x509_cert' => $this->samlIdpCertificate(),
            ],
        ]);

        return $application;
    }

    private function createPendingSamlRequest(Application $application): void
    {
        $initiator = User::factory()->create(['organization_id' => $application->organization_id]);

        SSOSession::factory()->forUser($initiator)->create([
            'application_id' => $application->id,
            'metadata' => ['pending' => true, 'saml_request_id' => 'request-1'],
        ]);
    }

    private function postSamlCallback(User $user): TestResponse
    {
        return $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml(
                $user->email,
                url('/api/v1/sso/saml/callback'),
                ' InResponseTo="request-1"'
            )),
            'RelayState' => 'request-1',
        ]);
    }

    private function postIdpInitiatedAssertion(User $user): TestResponse
    {
        return $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email, url('/api/v1/sso/saml/acs'))),
        ]);
    }

    private function verifyChallenge(string $challengeToken, User $user): TestResponse
    {
        return $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken,
            'totp_code' => $this->totpCodeFor($user),
        ]);
    }

    private function responseXml(string $email, string $recipient, string $inResponseTo = ''): string
    {
        $notOnOrAfter = gmdate('Y-m-d\TH:i:s\Z', time() + 300);

        return '<?xml version="1.0"?>'
            .'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response-1" Version="2.0">'
            .'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" Version="2.0">'
            .'<saml:Issuer>'.self::IDP_ENTITY_ID.'</saml:Issuer>'
            .'<saml:Subject><saml:NameID>'.$email.'</saml:NameID>'
            .'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            .'<saml:SubjectConfirmationData Recipient="'.$recipient.'" NotOnOrAfter="'.$notOnOrAfter.'"'.$inResponseTo.'/>'
            .'</saml:SubjectConfirmation></saml:Subject>'
            .'<saml:Conditions NotOnOrAfter="'.$notOnOrAfter.'"><saml:AudienceRestriction><saml:Audience>'.self::SP_ENTITY_ID.'</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            .'</saml:Assertion>'
            .'</samlp:Response>';
    }
}
