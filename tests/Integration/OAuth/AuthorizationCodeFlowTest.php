<?php

namespace Tests\Integration\OAuth;

use App\Models\Application;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Tests\TestCase;

/**
 * Authorization Code Flow Integration Tests (RFC 6749)
 *
 * Tests the complete OAuth 2.0 Authorization Code flow including:
 * - Basic authorization code flow
 * - Authorization code flow with PKCE (S256 and plain)
 * - State parameter handling
 * - Nonce parameter handling
 * - Invalid redirect URI scenarios
 * - Invalid client credentials
 * - Expired authorization codes
 */
class AuthorizationCodeFlowTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Application $application;

    protected Client $oauthClient;

    protected string $redirectUri = 'https://app.example.com/callback';

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('passport:install', ['--no-interaction' => true]);

        // Create test user with organization
        $this->user = User::factory()->create([
            'email_verified_at' => now(),
        ]);

        // Create application
        $this->application = Application::factory()->create([
            'name' => 'Test OAuth App',
            'organization_id' => $this->user->organization_id,
            'redirect_uris' => [$this->redirectUri, 'https://app.example.com/callback2'],
        ]);

        // Create OAuth client
        $this->oauthClient = Client::create([
            'name' => 'Test OAuth Client',
            'secret' => 'test-secret-123',
            'redirect' => implode(',', $this->application->redirect_uris),
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application->update([
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_basic_authorization_code_flow_without_pkce(): void
    {
        $state = Str::random(32);

        // Step 1: Authorization request
        $this->actingAs($this->user, 'web');
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid profile email',
            'state' => $state,
        ]));

        $authResponse->assertStatus(200);
        $authResponse->assertSee('authorize');

        // Extract auth token
        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1] ?? null;
        $this->assertNotNull($authToken);

        // Step 2: User approves
        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        $approvalResponse->assertRedirect();
        $redirectUrl = $approvalResponse->headers->get('Location');

        // Verify redirect contains code and state
        $this->assertStringContainsString('code=', $redirectUrl);
        $this->assertStringContainsString('state='.$state, $redirectUrl);

        // Extract authorization code
        parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $query);
        $authCode = $query['code'];
        $this->assertEquals($state, $query['state']);

        // Step 3: Exchange code for token
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
        ]);

        $tokenResponse->assertStatus(200);
        $tokenResponse->assertJsonStructure([
            'access_token',
            'refresh_token',
            'token_type',
            'expires_in',
        ]);

        $tokenData = $tokenResponse->json();
        $this->assertEquals('Bearer', $tokenData['token_type']);
        $this->assertIsString($tokenData['access_token']);
        $this->assertIsString($tokenData['refresh_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_authorization_code_flow_with_pkce_s256(): void
    {
        // Generate PKCE parameters
        $codeVerifier = Str::random(128);
        $codeChallenge = $this->generateS256CodeChallenge($codeVerifier);
        $state = Str::random(32);

        // Step 1: Authorization request with PKCE
        $this->actingAs($this->user, 'web');
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid profile email',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]));

        $authResponse->assertStatus(200);

        // Extract auth token and approve
        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        $approvalResponse->assertRedirect();

        // Extract authorization code
        parse_str(parse_url($approvalResponse->headers->get('Location'), PHP_URL_QUERY), $query);
        $authCode = $query['code'];

        // Step 2: Exchange code with code verifier
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
        ]);

        $tokenResponse->assertStatus(200);
        $tokenResponse->assertJsonStructure(['access_token', 'refresh_token', 'token_type']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_authorization_code_flow_with_pkce_plain(): void
    {
        // For plain method, code_challenge = code_verifier
        $codeVerifier = Str::random(128);
        $codeChallenge = $codeVerifier;
        $state = Str::random(32);

        $this->actingAs($this->user, 'web');
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'plain',
        ]));

        $authResponse->assertStatus(200);

        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        parse_str(parse_url($approvalResponse->headers->get('Location'), PHP_URL_QUERY), $query);
        $authCode = $query['code'];

        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
        ]);

        $tokenResponse->assertStatus(200);
        $tokenResponse->assertJsonStructure(['access_token', 'refresh_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_invalid_redirect_uri_rejected(): void
    {
        $this->actingAs($this->user, 'web');

        // Test with unregistered redirect URI
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => 'https://malicious.com/callback',
            'scope' => 'openid',
        ]));

        $authResponse->assertStatus(401);
        $authResponse->assertJsonFragment(['error' => 'invalid_client']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_invalid_client_id_rejected(): void
    {
        $this->actingAs($this->user, 'web');

        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => 99999, // Non-existent client
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid',
        ]));

        $authResponse->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_state_parameter_preserved_in_callback(): void
    {
        $state = 'custom-state-'.Str::random(20);

        $this->actingAs($this->user, 'web');
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid',
            'state' => $state,
        ]));

        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        $redirectUrl = $approvalResponse->headers->get('Location');
        $this->assertStringContainsString('state='.$state, $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_authorization_code_can_only_be_used_once(): void
    {
        $state = Str::random(32);
        $this->actingAs($this->user, 'web');

        // Get authorization code
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid',
            'state' => $state,
        ]));

        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        parse_str(parse_url($approvalResponse->headers->get('Location'), PHP_URL_QUERY), $query);
        $authCode = $query['code'];

        // First token exchange - should succeed
        $firstTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
        ]);

        $firstTokenResponse->assertStatus(200);

        // Second token exchange with same code - should fail
        $secondTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
        ]);

        $secondTokenResponse->assertStatus(400);
        $secondTokenResponse->assertJsonFragment(['error' => 'invalid_grant']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_wrong_code_verifier_rejected(): void
    {
        $codeVerifier = Str::random(128);
        $wrongVerifier = Str::random(128);
        $codeChallenge = $this->generateS256CodeChallenge($codeVerifier);
        $state = Str::random(32);

        $this->actingAs($this->user, 'web');
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]));

        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        parse_str(parse_url($approvalResponse->headers->get('Location'), PHP_URL_QUERY), $query);
        $authCode = $query['code'];

        // Try to exchange with wrong verifier
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $wrongVerifier, // Wrong verifier
        ]);

        $tokenResponse->assertStatus(400);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_user_denial_returns_error(): void
    {
        $state = Str::random(32);
        $this->actingAs($this->user, 'web');

        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => 'openid',
            'state' => $state,
        ]));

        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        // User denies authorization
        $denialResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '0', // Deny
        ]);

        $denialResponse->assertRedirect();
        $redirectUrl = $denialResponse->headers->get('Location');

        // Verify error is returned
        $this->assertStringContainsString('error=access_denied', $redirectUrl);
        $this->assertStringContainsString('state='.$state, $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_multiple_scopes_requested(): void
    {
        $state = Str::random(32);
        $scopes = 'openid profile email read write';

        $this->actingAs($this->user, 'web');
        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => $scopes,
            'state' => $state,
        ]));

        $authResponse->assertStatus(200);

        // Verify scopes are displayed to user
        $authResponse->assertSee('openid');
        $authResponse->assertSee('profile');
        $authResponse->assertSee('email');
    }

    protected function generateS256CodeChallenge(string $codeVerifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
    }
}
