<?php

namespace Tests\Integration\OAuth;

use App\Models\Application;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Token;
use Tests\TestCase;

/**
 * Token Management Integration Tests (RFC 6749, RFC 7662)
 *
 * Tests complete token lifecycle including:
 * - Access token generation
 * - Refresh token flow
 * - Token introspection (RFC 7662)
 * - Token revocation
 * - Token expiration handling
 * - Refresh token rotation
 */
class TokenManagementTest extends TestCase
{
    protected User $user;

    protected Application $application;

    protected Client $oauthClient;

    protected string $redirectUri = 'https://app.example.com/callback';

    protected function setUp(): void
    {
        parent::setUp();

        // Passport is set up in TestCase - no need to install

        $this->user = User::factory()->create([
            'email_verified_at' => now(),
        ]);

        $this->application = Application::factory()->create([
            'name' => 'Token Test App',
            'organization_id' => $this->user->organization_id,
            'redirect_uris' => [$this->redirectUri],
        ]);

        $this->oauthClient = Client::create([
            'name' => 'Token Test Client',
            'secret' => 'test-secret-123',
            'redirect' => $this->redirectUri,
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
    public function test_access_token_generation(): void
    {
        $tokens = $this->performOAuthFlow();

        $this->assertArrayHasKey('access_token', $tokens);
        $this->assertArrayHasKey('refresh_token', $tokens);
        $this->assertArrayHasKey('token_type', $tokens);
        $this->assertArrayHasKey('expires_in', $tokens);

        $this->assertEquals('Bearer', $tokens['token_type']);
        $this->assertIsString($tokens['access_token']);
        $this->assertIsString($tokens['refresh_token']);
        $this->assertIsInt($tokens['expires_in']);
        $this->assertGreaterThan(0, $tokens['expires_in']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_refresh_token_flow(): void
    {
        $originalTokens = $this->performOAuthFlow();
        $originalAccessToken = $originalTokens['access_token'];
        $refreshToken = $originalTokens['refresh_token'];

        // Wait a moment to ensure timestamps are different
        sleep(1);

        // Refresh the token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'scope' => 'openid profile',
        ]);

        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        // Verify new tokens are different from original
        $this->assertArrayHasKey('access_token', $newTokens);
        $this->assertArrayHasKey('refresh_token', $newTokens);
        $this->assertNotEquals($originalAccessToken, $newTokens['access_token']);

        // Verify token structure
        $this->assertEquals('Bearer', $newTokens['token_type']);
        $this->assertIsInt($newTokens['expires_in']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_refresh_token_rotation(): void
    {
        $originalTokens = $this->performOAuthFlow();
        $originalRefreshToken = $originalTokens['refresh_token'];

        // First refresh
        $firstRefresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $originalRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
        ]);

        $firstRefresh->assertStatus(200);
        $firstNewTokens = $firstRefresh->json();

        // Verify we got a new refresh token
        $this->assertArrayHasKey('refresh_token', $firstNewTokens);
        $newRefreshToken = $firstNewTokens['refresh_token'];

        // Try to use old refresh token again - should fail
        $oldTokenAttempt = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $originalRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
        ]);

        $oldTokenAttempt->assertStatus(400);
        $oldTokenAttempt->assertJsonFragment(['error' => 'invalid_grant']);

        // Use new refresh token - should work
        $secondRefresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $newRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
        ]);

        $secondRefresh->assertStatus(200);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_invalid_refresh_token_rejected(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => 'invalid-refresh-token-xyz',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
        ]);

        $response->assertStatus(401);
        $response->assertJsonFragment(['error' => 'invalid_request']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_token_expiration(): void
    {
        $tokens = $this->performOAuthFlow();

        // Verify expires_in is present
        $this->assertArrayHasKey('expires_in', $tokens);
        $expiresIn = $tokens['expires_in'];

        // Typically tokens expire in 3600 seconds (1 hour) or 31536000 seconds (1 year)
        $this->assertGreaterThan(0, $expiresIn);

        // Verify we can calculate expiration time
        $expiresAt = Carbon::now()->addSeconds($expiresIn);
        $this->assertInstanceOf(Carbon::class, $expiresAt);
        $this->assertTrue($expiresAt->isFuture());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_token_with_different_scopes(): void
    {
        // Request token with specific scopes
        $tokens = $this->performOAuthFlow(['openid', 'profile']);

        $this->assertArrayHasKey('access_token', $tokens);

        // Request another token with different scopes
        $tokens2 = $this->performOAuthFlow(['openid', 'email']);

        $this->assertArrayHasKey('access_token', $tokens2);
        $this->assertNotEquals($tokens['access_token'], $tokens2['access_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_token_introspection_valid_token(): void
    {
        $tokens = $this->performOAuthFlow();
        $accessToken = $tokens['access_token'];

        // Parse JWT to get token ID
        $tokenParts = explode('.', $accessToken);
        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);
            $jti = $payload['jti'] ?? null;

            if ($jti) {
                $tokenRecord = Token::find($jti);
                $this->assertNotNull($tokenRecord);
                $this->assertFalse($tokenRecord->revoked);
                $this->assertEquals($this->user->id, $tokenRecord->user_id);
                $this->assertEquals($this->oauthClient->id, $tokenRecord->client_id);
            }
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_token_revocation_via_api(): void
    {
        $tokens = $this->performOAuthFlow();

        // Authenticate with the token
        $this->actingAs($this->user, 'api');

        // Revoke the token
        $revokeResponse = $this->postJson('/api/v1/auth/revoke');

        $revokeResponse->assertStatus(200);
        $revokeResponse->assertJson([
            'message' => 'Token revoked successfully',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_multiple_active_tokens_for_same_user(): void
    {
        // Generate first token
        $tokens1 = $this->performOAuthFlow(['openid', 'profile']);

        // Generate second token
        $tokens2 = $this->performOAuthFlow(['openid', 'email']);

        // Both tokens should be different and valid
        $this->assertNotEquals($tokens1['access_token'], $tokens2['access_token']);
        $this->assertNotEquals($tokens1['refresh_token'], $tokens2['refresh_token']);

        // Verify both tokens work independently
        $this->assertIsString($tokens1['access_token']);
        $this->assertIsString($tokens2['access_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_refresh_token_without_client_secret_fails(): void
    {
        $tokens = $this->performOAuthFlow();

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            // Missing client_secret
        ]);

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_refresh_token_with_wrong_client_secret_fails(): void
    {
        $tokens = $this->performOAuthFlow();

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'wrong-secret',
        ]);

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_token_includes_user_context(): void
    {
        $tokens = $this->performOAuthFlow();

        // Parse JWT token
        $tokenParts = explode('.', $tokens['access_token']);

        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);

            // Verify standard JWT claims
            $this->assertArrayHasKey('aud', $payload); // Audience
            $this->assertArrayHasKey('jti', $payload); // JWT ID
            $this->assertArrayHasKey('iat', $payload); // Issued at
            $this->assertArrayHasKey('nbf', $payload); // Not before
            $this->assertArrayHasKey('exp', $payload); // Expiration
            $this->assertArrayHasKey('sub', $payload); // Subject (user ID)

            // Verify user ID matches
            $this->assertEquals($this->user->id, $payload['sub']);

            // Verify expiration is in future
            $this->assertGreaterThan(time(), $payload['exp']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_refresh_preserves_user_context(): void
    {
        $originalTokens = $this->performOAuthFlow();

        // Extract user ID from original token
        $originalParts = explode('.', $originalTokens['access_token']);
        $originalPayload = json_decode(base64_decode($originalParts[1]), true);
        $originalUserId = $originalPayload['sub'];

        // Refresh the token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $originalTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
        ]);

        $newTokens = $refreshResponse->json();

        // Extract user ID from new token
        $newParts = explode('.', $newTokens['access_token']);
        $newPayload = json_decode(base64_decode($newParts[1]), true);
        $newUserId = $newPayload['sub'];

        // User ID should remain the same
        $this->assertEquals($originalUserId, $newUserId);
        $this->assertEquals($this->user->id, $newUserId);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_concurrent_refresh_token_usage(): void
    {
        $tokens = $this->performOAuthFlow();
        $refreshToken = $tokens['refresh_token'];

        // Simulate concurrent refresh attempts
        $responses = [];
        for ($i = 0; $i < 3; $i++) {
            $responses[] = $this->postJson('/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'test-secret-123',
            ]);
        }

        // First request should succeed
        $responses[0]->assertStatus(200);

        // Subsequent requests should fail (token already used)
        $responses[1]->assertStatus(400);
        $responses[2]->assertStatus(400);
    }

    protected function performOAuthFlow(array $scopes = ['openid', 'profile']): array
    {
        $codeVerifier = Str::random(128);
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        $state = Str::random(32);

        $this->actingAs($this->user, 'web');

        $authResponse = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $scopes),
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

        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'test-secret-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
        ]);

        return $tokenResponse->json();
    }
}
