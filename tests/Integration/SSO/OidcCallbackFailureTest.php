<?php

namespace Tests\Integration\SSO;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class OidcCallbackFailureTest extends IntegrationTestCase
{
    private const CALLBACK_URL = 'https://app.example.com/callback';

    private const TOKEN_ENDPOINT = 'https://idp.example.com/token';

    private const USERINFO_ENDPOINT = 'https://idp.example.com/userinfo';

    private User $user;

    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();

        $this->user = User::factory()->create(['email' => 'Jane.Doe@example.com']);
        $this->application = Application::factory()->create(['organization_id' => $this->user->organization_id]);
        $this->user->applications()->attach($this->application->id, ['granted_at' => now()]);

        SSOConfiguration::factory()->create([
            'application_id' => $this->application->id,
            'provider' => 'oidc',
            'callback_url' => self::CALLBACK_URL,
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

        Passport::actingAs($this->user, ['sso']);
    }

    #[Test]
    public function it_creates_no_session_when_the_token_endpoint_times_out(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => fn () => throw new ConnectionException('Connection timed out'),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_connection_timeout');
    }

    #[Test]
    public function it_creates_no_session_when_the_token_endpoint_returns_an_error(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['error' => 'invalid_grant'], 400),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_token_exchange_failed');
        Http::assertNotSent(fn (Request $request) => $request->url() === self::USERINFO_ENDPOINT);
    }

    #[Test]
    public function it_creates_no_session_when_the_token_response_has_no_access_token(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['id_token' => 'idp-id-token', 'token_type' => 'Bearer']),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_token_exchange_failed');
        Http::assertNotSent(fn (Request $request) => $request->url() === self::USERINFO_ENDPOINT);
    }

    #[Test]
    public function it_creates_no_session_when_userinfo_fails(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-access-token']),
            self::USERINFO_ENDPOINT => Http::response(['error' => 'server_error'], 500),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_userinfo_failed');
    }

    #[Test]
    public function it_creates_no_session_when_the_idp_email_differs_from_the_session_user(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-access-token']),
            self::USERINFO_ENDPOINT => Http::response(['sub' => 'idp-user', 'email' => 'someone.else@example.com']),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_identity_mismatch');
    }

    #[Test]
    public function it_creates_no_session_when_userinfo_has_no_email(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-access-token']),
            self::USERINFO_ENDPOINT => Http::response(['sub' => 'idp-user']),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_identity_mismatch');
    }

    #[Test]
    public function it_issues_the_session_when_the_idp_email_differs_only_in_case(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-access-token']),
            self::USERINFO_ENDPOINT => Http::response(['sub' => 'idp-user', 'email' => 'jane.doe@EXAMPLE.com']),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $response->assertOk()->assertJsonPath('success', true)->assertJsonPath('user.id', $this->user->id);
        $this->assertNotEmpty($response->json('session.session_token'));
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $this->user->id, 'event' => 'sso_login_success', 'success' => true]);
    }

    #[Test]
    public function it_does_not_extend_an_existing_session_on_a_failed_exchange(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['error' => 'invalid_grant'], 400),
        ]);
        $existing = SSOSession::factory()->forUser($this->user)->create([
            'application_id' => $this->application->id,
            'expires_at' => now()->addMinutes(30),
        ]);
        $before = $existing->fresh();
        $state = $this->initiate();
        $this->assertNotSame($existing->id, SSOSession::where('external_session_id', $state)->sole()->id);
        $this->travel(5)->minutes();

        $response = $this->postCallback($state);

        $this->assertFailedWithoutSession($response, $state, 'sso_token_exchange_failed', 1);
        $after = $existing->fresh();
        $this->assertTrue($after->isActive());
        $this->assertSame($before->session_token, $after->session_token);
        $this->assertEquals($before->expires_at, $after->expires_at);
        $this->assertArrayNotHasKey('access_token', $after->metadata ?? []);
    }

    #[Test]
    public function it_stores_no_id_or_refresh_token_that_is_not_a_non_empty_string(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-access-token', 'id_token' => ['forged'], 'refresh_token' => 42]),
            self::USERINFO_ENDPOINT => Http::response(['sub' => 'idp-user', 'email' => $this->user->email]),
        ]);
        $state = $this->initiate();

        $response = $this->postCallback($state);

        $response->assertOk()->assertJsonPath('success', true);
        $metadata = SSOSession::where('session_token', $response->json('session.session_token'))->sole()->metadata;
        $this->assertSame('idp-access-token', $metadata['access_token']);
        $this->assertNull($metadata['id_token']);
        $this->assertNull($metadata['refresh_token']);
    }

    #[Test]
    public function it_refreshes_through_the_token_endpoint(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-refreshed-access-token', 'refresh_token' => 'idp-rotated-refresh-token']),
        ]);
        $session = $this->sessionWithIdpRefreshToken('idp-refresh-token');
        $localRefreshToken = $session->refresh_token;

        $response = $this->postJson("/api/v1/sso/sessions/{$session->session_token}/refresh");

        $response->assertOk()
            ->assertJsonPath('success', true)
            ->assertJsonPath('access_token', 'idp-refreshed-access-token');
        Http::assertSent(fn (Request $request) => $request->url() === self::TOKEN_ENDPOINT
            && $request['grant_type'] === 'refresh_token'
            && $request['refresh_token'] === 'idp-refresh-token'
            && $request['client_id'] === 'client');
        $session = $session->fresh();
        $this->assertSame('idp-refreshed-access-token', $session->metadata['access_token']);
        $this->assertSame('idp-rotated-refresh-token', $session->metadata['refresh_token']);
        $this->assertSame($localRefreshToken, $session->refresh_token);
    }

    #[Test]
    public function it_keeps_the_idp_refresh_token_when_the_refresh_response_has_no_string_refresh_token(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['access_token' => 'idp-refreshed-access-token', 'refresh_token' => ['forged']]),
        ]);
        $session = $this->sessionWithIdpRefreshToken('idp-refresh-token');
        $localRefreshToken = $session->refresh_token;

        $response = $this->postJson("/api/v1/sso/sessions/{$session->session_token}/refresh");

        $response->assertOk()->assertJsonPath('access_token', 'idp-refreshed-access-token');
        $session = $session->fresh();
        $this->assertSame('idp-refresh-token', $session->metadata['refresh_token']);
        $this->assertSame($localRefreshToken, $session->refresh_token);
    }

    #[Test]
    public function it_fails_a_refresh_when_the_session_has_no_idp_refresh_token(): void
    {
        Http::fake();
        $session = SSOSession::factory()->forUser($this->user)->create(['application_id' => $this->application->id]);

        $response = $this->postJson("/api/v1/sso/sessions/{$session->session_token}/refresh");

        $response->assertStatus(400)
            ->assertJsonPath('success', false)
            ->assertJsonPath('message', 'Invalid or expired refresh token');
        Http::assertNothingSent();
        $this->assertArrayNotHasKey('token_updated_at', $session->fresh()->metadata ?? []);
    }

    #[Test]
    public function it_rejects_a_refresh_the_idp_refuses(): void
    {
        Http::fake([
            self::TOKEN_ENDPOINT => Http::response(['error' => 'invalid_grant'], 400),
        ]);
        $session = $this->sessionWithIdpRefreshToken('idp-refresh-token');
        $refreshToken = $session->refresh_token;

        $response = $this->postJson("/api/v1/sso/sessions/{$session->session_token}/refresh");

        $response->assertStatus(400)->assertJsonPath('success', false)->assertJsonMissingPath('access_token');
        Http::assertSentCount(1);
        $session = $session->fresh();
        $this->assertSame($refreshToken, $session->refresh_token);
        $this->assertSame('idp-refresh-token', $session->metadata['refresh_token']);
        $this->assertArrayNotHasKey('token_updated_at', $session->metadata ?? []);
    }

    private function sessionWithIdpRefreshToken(string $idpRefreshToken): SSOSession
    {
        return SSOSession::factory()->forUser($this->user)->create([
            'application_id' => $this->application->id,
            'metadata' => ['refresh_token' => $idpRefreshToken],
        ]);
    }

    private function initiate(): string
    {
        return $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->application->ssoConfiguration->id,
            'redirect_uri' => self::CALLBACK_URL,
        ])->assertOk()->json('state');
    }

    private function postCallback(string $state): TestResponse
    {
        return $this->postJson('/api/v1/sso/callback', ['code' => 'idp-code', 'state' => $state]);
    }

    private function assertFailedWithoutSession(TestResponse $response, string $state, string $event, int $remainingSessions = 0): void
    {
        $response->assertStatus(400)
            ->assertJsonPath('success', false)
            ->assertJsonPath('error', 'SSO authentication failed')
            ->assertJsonMissingPath('session')
            ->assertJsonMissingPath('tokens');

        $this->assertSame($remainingSessions, SSOSession::where('user_id', $this->user->id)->where('application_id', $this->application->id)->count());
        $this->assertDatabaseMissing('sso_sessions', ['external_session_id' => $state]);

        $this->assertDatabaseHas('authentication_logs', ['user_id' => $this->user->id, 'event' => $event, 'success' => false]);
        $this->assertDatabaseMissing('authentication_logs', ['user_id' => $this->user->id, 'success' => true, 'event' => $event]);
        $this->assertDatabaseMissing('authentication_logs', ['user_id' => $this->user->id, 'event' => 'sso_login_success']);

        $this->postCallback($state)->assertStatus(400)->assertJsonPath('success', false)->assertJsonMissingPath('session');
    }
}
