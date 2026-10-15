<?php

namespace Tests\Integration\SSO;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SsoPendingSessionLifecycleTest extends IntegrationTestCase
{
    use SignsSamlResponses;

    private const OIDC_CALLBACK_URL = 'https://app.example.com/callback';

    private const SAML_CALLBACK_URL = 'https://app.example.com/saml/callback';

    private const TOKEN_ENDPOINT = 'https://idp.example.com/token';

    private const USERINFO_ENDPOINT = 'https://idp.example.com/userinfo';

    private const IDP_ENTITY_ID = 'https://idp.example.com';

    private const SP_ENTITY_ID = 'https://authos.example.com/saml/sp';

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();
    }

    #[Test]
    public function it_replaces_the_pending_saml_session_with_an_issued_one(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createSamlConfiguration($user);
        $state = $this->initiate($user, $configuration, self::SAML_CALLBACK_URL)->json('state');

        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => $this->signSamlResponse($this->samlResponseXml($user->email)),
            'RelayState' => $state,
        ]);

        $response->assertOk()
            ->assertJsonStructure([
                'success',
                'user' => ['id', 'name', 'email'],
                'session' => ['id', 'session_token', 'token', 'expires_at'],
                'application' => ['id', 'name'],
                'tokens' => ['access_token', 'token_type', 'expires_in'],
            ])
            ->assertJsonPath('success', true)
            ->assertJsonPath('application.id', $configuration->application_id);
        $this->assertDatabaseMissing('sso_sessions', ['external_session_id' => $state]);
        $active = SSOSession::where('user_id', $user->id)->where('application_id', $configuration->application_id)->active()->sole();
        $this->assertSame($active->session_token, $response->json('session.session_token'));
        $this->assertArrayNotHasKey('pending', $active->metadata ?? []);
    }

    #[Test]
    public function it_returns_the_issued_session_shape_from_the_oidc_callback(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user);
        $state = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL)->json('state');

        $response = $this->postOidcCallback($state);

        $response->assertOk()
            ->assertExactJsonStructure([
                'success',
                'user' => ['id', 'name', 'email'],
                'session' => ['session_token', 'expires_at'],
                'application' => ['id', 'name'],
            ])
            ->assertJsonPath('success', true)
            ->assertJsonPath('application.id', $configuration->application_id);
        $this->assertDatabaseMissing('sso_sessions', ['external_session_id' => $state]);
        $issued = SSOSession::where('session_token', $response->json('session.session_token'))->sole();
        $this->assertArrayNotHasKey('pending', $issued->metadata);
        $this->postJson('/api/v1/sso/validate', ['token' => $issued->session_token])->assertOk();
    }

    #[Test]
    public function it_keeps_an_existing_live_session_when_an_mfa_user_completes_an_oidc_callback(): void
    {
        $user = User::factory()->withMfa()->create();
        $configuration = $this->createOidcConfiguration($user);
        $live = $this->createLiveSession($user, $configuration);
        $state = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL)->json('state');

        $response = $this->postOidcCallback($state);

        $response->assertStatus(202)->assertJsonPath('mfa_required', true);
        $this->assertDatabaseMissing('sso_sessions', ['external_session_id' => $state]);
        $this->assertLiveSessionUntouched($live);
    }

    #[Test]
    public function it_keeps_an_existing_live_session_when_a_user_completes_an_oidc_callback(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user);
        $live = $this->createLiveSession($user, $configuration);
        $state = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL)->json('state');

        $response = $this->postOidcCallback($state);

        $response->assertOk()->assertJsonPath('success', true);
        $this->assertDatabaseMissing('sso_sessions', ['external_session_id' => $state]);
        $this->assertTrue($live->fresh()->isActive());
        $this->postJson('/api/v1/sso/validate', ['token' => $live->session_token])->assertOk();
    }

    #[Test]
    public function it_does_not_validate_the_pending_session_before_the_callback(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user);

        $initiate = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL);

        $initiate->assertJsonMissingPath('session_token');
        $pending = SSOSession::where('external_session_id', $initiate->json('state'))->sole();
        $this->postJson('/api/v1/sso/validate', ['token' => $pending->session_token])->assertUnauthorized();
        $this->postJson('/api/v1/sso/refresh', ['refresh_token' => $pending->refresh_token])->assertStatus(400);
        $this->getJson("/api/v1/sso/sessions/{$pending->session_token}/validate")->assertStatus(400)->assertJsonPath('valid', false);
        $this->postJson("/api/v1/sso/sessions/{$pending->session_token}/refresh")->assertStatus(400);
        $this->assertSame(0, SSOSession::where('user_id', $user->id)->active()->count());
    }

    #[Test]
    public function it_does_not_validate_the_pending_session_after_a_failed_callback(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user, Http::response(['error' => 'invalid_grant'], 400));
        $state = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL)->json('state');
        $pending = SSOSession::where('external_session_id', $state)->sole();

        $response = $this->postOidcCallback($state);

        $response->assertStatus(400)->assertJsonPath('success', false);
        $this->assertDatabaseMissing('sso_sessions', ['id' => $pending->id]);
        $this->postJson('/api/v1/sso/validate', ['token' => $pending->session_token])->assertUnauthorized();
        $this->postJson('/api/v1/sso/refresh', ['refresh_token' => $pending->refresh_token])->assertStatus(400);
    }

    #[Test]
    public function it_creates_a_separate_pending_row_when_a_live_session_exists(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user);
        $live = $this->createLiveSession($user, $configuration);
        $this->travel(5)->minutes();

        $state = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL)->json('state');

        $pending = SSOSession::where('external_session_id', $state)->sole();
        $this->assertNotSame($live->id, $pending->id);
        $this->assertLiveSessionUntouched($live);
    }

    #[Test]
    public function it_gives_the_pending_row_a_ten_minute_lifetime(): void
    {
        $user = User::factory()->create();
        $configuration = $this->createOidcConfiguration($user);

        $state = $this->initiate($user, $configuration, self::OIDC_CALLBACK_URL)->json('state');

        $pending = SSOSession::where('external_session_id', $state)->sole();
        $this->assertTrue($pending->expires_at->between(now()->addMinutes(9), now()->addMinutes(10)->addSecond()));
    }

    private function assertLiveSessionUntouched(SSOSession $live): void
    {
        $after = $live->fresh();
        $this->assertNotNull($after);
        $this->assertTrue($after->isActive());
        $this->assertSame($live->session_token, $after->session_token);
        $this->assertSame($live->refresh_token, $after->refresh_token);
        $this->assertEquals($live->expires_at, $after->expires_at);
    }

    private function createLiveSession(User $user, SSOConfiguration $configuration): SSOSession
    {
        return SSOSession::factory()->forUser($user)->create([
            'application_id' => $configuration->application_id,
            'expires_at' => now()->addMinutes(30),
        ])->fresh();
    }

    private function initiate(User $user, SSOConfiguration $configuration, string $redirectUri): TestResponse
    {
        Passport::actingAs($user, ['sso']);

        return $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $configuration->application_id,
            'sso_configuration_id' => $configuration->id,
            'redirect_uri' => $redirectUri,
        ])->assertOk();
    }

    private function postOidcCallback(string $state): TestResponse
    {
        return $this->postJson('/api/v1/sso/callback', ['code' => 'idp-code', 'state' => $state]);
    }

    private function createApplicationFor(User $user): Application
    {
        $application = Application::factory()->create(['organization_id' => $user->organization_id]);
        $user->applications()->attach($application->id, ['granted_at' => now()]);

        return $application;
    }

    private function createOidcConfiguration(User $user, mixed $tokenResponse = null): SSOConfiguration
    {
        Http::fake([
            self::TOKEN_ENDPOINT => $tokenResponse ?? Http::response([
                'access_token' => 'idp-access-token',
                'id_token' => 'idp-id-token',
                'refresh_token' => 'idp-refresh-token',
            ]),
            self::USERINFO_ENDPOINT => Http::response(['sub' => 'idp-user', 'email' => $user->email]),
        ]);

        return SSOConfiguration::factory()->create([
            'application_id' => $this->createApplicationFor($user)->id,
            'provider' => 'oidc',
            'callback_url' => self::OIDC_CALLBACK_URL,
            'allowed_domains' => ['app.example.com'],
            'session_lifetime' => 3600,
            'configuration' => [
                'client_id' => 'client',
                'client_secret' => 'secret',
                'authorization_endpoint' => 'https://idp.example.com/auth',
                'token_endpoint' => self::TOKEN_ENDPOINT,
                'userinfo_endpoint' => self::USERINFO_ENDPOINT,
            ],
            'is_active' => true,
        ]);
    }

    private function createSamlConfiguration(User $user): SSOConfiguration
    {
        return SSOConfiguration::create([
            'application_id' => $this->createApplicationFor($user)->id,
            'name' => 'SAML IdP',
            'provider' => 'saml2',
            'callback_url' => self::SAML_CALLBACK_URL,
            'logout_url' => 'https://app.example.com/saml/logout',
            'allowed_domains' => ['app.example.com'],
            'session_lifetime' => 3600,
            'is_active' => true,
            'configuration' => [
                'idp_entity_id' => self::IDP_ENTITY_ID,
                'sp_entity_id' => self::SP_ENTITY_ID,
                'x509_cert' => $this->samlIdpCertificate(),
            ],
        ]);
    }

    private function samlResponseXml(string $email): string
    {
        $notOnOrAfter = gmdate('Y-m-d\TH:i:s\Z', time() + 300);

        return '<?xml version="1.0"?>'
            .'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response-1" Version="2.0">'
            .'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" Version="2.0">'
            .'<saml:Issuer>'.self::IDP_ENTITY_ID.'</saml:Issuer>'
            .'<saml:Subject><saml:NameID>'.$email.'</saml:NameID>'
            .'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            .'<saml:SubjectConfirmationData Recipient="'.url('/api/v1/sso/saml/callback').'" NotOnOrAfter="'.$notOnOrAfter.'"/>'
            .'</saml:SubjectConfirmation></saml:Subject>'
            .'<saml:Conditions NotOnOrAfter="'.$notOnOrAfter.'"><saml:AudienceRestriction><saml:Audience>'.self::SP_ENTITY_ID.'</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            .'</saml:Assertion>'
            .'</samlp:Response>';
    }
}
