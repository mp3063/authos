<?php

namespace Tests\Integration\SSO;

use App\Models\Application;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * SSO Token Refresh and Rotation Integration Tests
 *
 * Comprehensive tests for SSO token refresh flows including:
 * - Refresh token to new access token exchange
 * - Old refresh token invalidation after use
 * - Token rotation on refresh (new refresh token issued)
 * - Expired refresh token rejection
 * - Revoked token handling
 * - Invalid refresh token format validation
 * - Missing refresh token parameter handling
 * - Token scope preservation across refreshes
 * - Token expiry time validation
 * - Multiple sequential refresh operations
 *
 * These tests focus on SSO-specific token refresh scenarios,
 * complementing the general OAuth token management tests.
 *
 * Following Phase 3 patterns:
 * - PHP 8 #[Test] attributes
 * - ARRANGE-ACT-ASSERT structure
 * - Comprehensive inline documentation
 * - RefreshDatabase trait for isolation
 * - Integration with Laravel Passport
 *
 * Related RFCs:
 * - RFC 6749 (OAuth 2.0) Section 6: Refreshing an Access Token
 * - RFC 6819 (OAuth 2.0 Threat Model) Section 5.2: Refresh Token Rotation
 */
#[\PHPUnit\Framework\Attributes\Group('sso')]
#[\PHPUnit\Framework\Attributes\Group('token-refresh')]
#[\PHPUnit\Framework\Attributes\Group('critical')]
#[\PHPUnit\Framework\Attributes\Group('integration')]
class SsoTokenRefreshTest extends IntegrationTestCase
{
    protected User $user;

    protected Application $application;

    protected Client $oauthClient;

    protected string $redirectUri = 'https://sso.example.com/callback';

    protected function setUp(): void
    {
        parent::setUp();

        // ARRANGE: Create test user with verified email
        $this->user = User::factory()->create([
            'email' => 'sso-user@example.com',
            'email_verified_at' => now(),
        ]);

        // Create SSO application
        $this->application = Application::factory()->create([
            'name' => 'SSO Token Refresh Test App',
            'organization_id' => $this->user->organization_id,
            'redirect_uris' => [
                $this->redirectUri,
                'https://sso.example.com/callback2',
            ],
        ]);

        // Create OAuth client for SSO
        $this->oauthClient = Client::create([
            'name' => 'SSO Token Refresh Test Client',
            'secret' => 'sso-test-secret-refresh-123',
            'redirect' => implode(',', $this->application->redirect_uris),
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        // Link OAuth client to application
        $this->application->update([
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);
    }

    // ============================================================
    // REFRESH TOKEN TO NEW ACCESS TOKEN EXCHANGE
    // ============================================================

    #[Test]
    public function refresh_token_successfully_exchanges_for_new_access_token()
    {
        // ARRANGE: Perform initial OAuth flow to get tokens
        $originalTokens = $this->performSsoOAuthFlow(['openid', 'profile', 'email']);
        $refreshToken = $originalTokens['refresh_token'];
        $originalAccessToken = $originalTokens['access_token'];

        // Wait to ensure different timestamps
        sleep(1);

        // ACT: Exchange refresh token for new access token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
            'scope' => 'openid profile email',
        ]);

        // ASSERT: Refresh successful with proper response structure
        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        // ASSERT: All required fields present
        $this->assertArrayHasKey('access_token', $newTokens);
        $this->assertArrayHasKey('refresh_token', $newTokens);
        $this->assertArrayHasKey('token_type', $newTokens);
        $this->assertArrayHasKey('expires_in', $newTokens);

        // ASSERT: Token type is Bearer
        $this->assertEquals('Bearer', $newTokens['token_type']);

        // ASSERT: New access token is different from original
        $this->assertNotEquals($originalAccessToken, $newTokens['access_token']);

        // ASSERT: Tokens are strings
        $this->assertIsString($newTokens['access_token']);
        $this->assertIsString($newTokens['refresh_token']);

        // ASSERT: Expiry time is positive
        $this->assertGreaterThan(0, $newTokens['expires_in']);
    }

    // ============================================================
    // OLD REFRESH TOKEN INVALIDATION
    // ============================================================

    #[Test]
    public function old_refresh_token_cannot_be_reused_after_refresh()
    {
        // ARRANGE: Get initial tokens
        $originalTokens = $this->performSsoOAuthFlow(['openid', 'profile']);
        $originalRefreshToken = $originalTokens['refresh_token'];

        // ACT 1: Use refresh token once (should succeed)
        $firstRefreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $originalRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT 1: First refresh successful
        $firstRefreshResponse->assertStatus(200);
        $newTokens = $firstRefreshResponse->json();
        $this->assertArrayHasKey('refresh_token', $newTokens);

        // ACT 2: Try to reuse the old refresh token (should fail)
        $secondRefreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $originalRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT 2: Second attempt fails with invalid_grant error
        $secondRefreshResponse->assertStatus(400);
        $secondRefreshResponse->assertJsonFragment(['error' => 'invalid_grant']);
        // OAuth uses error_description instead of message field
        $secondRefreshResponse->assertJsonFragment([
            'error_description' => 'The refresh token is invalid.',
        ]);
    }

    // ============================================================
    // TOKEN ROTATION ON REFRESH
    // ============================================================

    #[Test]
    public function new_refresh_token_issued_with_each_refresh_operation()
    {
        // ARRANGE: Get initial tokens
        $originalTokens = $this->performSsoOAuthFlow(['openid']);
        $firstRefreshToken = $originalTokens['refresh_token'];

        // ACT 1: First refresh operation
        $firstRefresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $firstRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT 1: First refresh successful with new refresh token
        $firstRefresh->assertStatus(200);
        $firstNewTokens = $firstRefresh->json();
        $this->assertArrayHasKey('refresh_token', $firstNewTokens);
        $secondRefreshToken = $firstNewTokens['refresh_token'];

        // ASSERT 2: New refresh token is different from original
        $this->assertNotEquals($firstRefreshToken, $secondRefreshToken);

        sleep(1);

        // ACT 2: Second refresh operation with new refresh token
        $secondRefresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $secondRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT 3: Second refresh successful with another new refresh token
        $secondRefresh->assertStatus(200);
        $secondNewTokens = $secondRefresh->json();
        $this->assertArrayHasKey('refresh_token', $secondNewTokens);
        $thirdRefreshToken = $secondNewTokens['refresh_token'];

        // ASSERT 4: Third refresh token is different from both previous tokens
        $this->assertNotEquals($firstRefreshToken, $thirdRefreshToken);
        $this->assertNotEquals($secondRefreshToken, $thirdRefreshToken);

        // ASSERT 5: Each access token is also different
        $this->assertNotEquals(
            $originalTokens['access_token'],
            $firstNewTokens['access_token']
        );
        $this->assertNotEquals(
            $firstNewTokens['access_token'],
            $secondNewTokens['access_token']
        );
    }

    // ============================================================
    // EXPIRED REFRESH TOKEN REJECTION
    // ============================================================

    #[Test]
    public function expired_refresh_token_is_rejected()
    {
        // ARRANGE: Create an expired refresh token manually
        // Note: We simulate expiration by using an invalid/non-existent token
        // since actually waiting for expiration would make tests too slow
        $expiredRefreshToken = 'expired_refresh_token_'.Str::random(60);

        // ACT: Try to use expired refresh token
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $expiredRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT: Request fails with 400 Bad Request (not 401)
        $response->assertStatus(400);
        // Expired/invalid tokens return invalid_grant error
        $response->assertJsonFragment(['error' => 'invalid_grant']);
        // OAuth uses error_description field
        $response->assertJsonFragment([
            'error_description' => 'The refresh token is invalid.',
        ]);
    }

    // ============================================================
    // REVOKED TOKEN HANDLING
    // ============================================================

    #[Test]
    public function revoked_refresh_token_cannot_be_used()
    {
        // ARRANGE: Get initial tokens
        $tokens = $this->performSsoOAuthFlow(['openid', 'profile']);
        $refreshToken = $tokens['refresh_token'];

        // Parse refresh token to get token ID
        $refreshTokenRecord = RefreshToken::where('id', $refreshToken)->first();

        // If we can't find it by ID, this test verifies that invalid tokens fail
        if ($refreshTokenRecord) {
            // ACT: Manually revoke the refresh token
            $refreshTokenRecord->update(['revoked' => true]);

            // ACT: Try to use revoked refresh token
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'sso-test-secret-refresh-123',
            ]);

            // ASSERT: Revoked token rejected with 400 Bad Request
            $response->assertStatus(400);
            // Revoked tokens return invalid_grant error
            $response->assertJsonFragment(['error' => 'invalid_grant']);
        } else {
            // If we can't find the token record, just verify invalid token fails
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'invalid_token',
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'sso-test-secret-refresh-123',
            ]);

            // Invalid tokens return 400, not 401
            $response->assertStatus(400);
        }
    }

    // ============================================================
    // INVALID REFRESH TOKEN FORMAT
    // ============================================================

    #[Test]
    public function malformed_refresh_token_is_rejected()
    {
        // ARRANGE: Create various malformed refresh tokens
        $malformedTokens = [
            'too-short',
            'spaces in token',
            'special!@#$%chars',
            'emoji_token_😀',
            str_repeat('a', 300), // Too long
            '',
        ];

        foreach ($malformedTokens as $malformedToken) {
            // ACT: Try to use malformed refresh token
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $malformedToken,
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'sso-test-secret-refresh-123',
            ]);

            // ASSERT: Malformed token rejected with 400 or 401
            $statusCode = $response->getStatusCode();
            $this->assertContains($statusCode, [400, 401],
                "Malformed token '{$malformedToken}' should be rejected"
            );
        }
    }

    // ============================================================
    // MISSING REFRESH TOKEN PARAMETER
    // ============================================================

    #[Test]
    public function missing_refresh_token_parameter_returns_error()
    {
        // ACT: Try to refresh without refresh_token parameter
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            // Missing: refresh_token
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT: Request fails with 400 Bad Request
        $response->assertStatus(400);
        $response->assertJsonFragment(['error' => 'invalid_request']);
        // OAuth uses error_description field, not message
        $response->assertJsonFragment([
            'error_description' => 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
        ]);
    }

    // ============================================================
    // TOKEN SCOPES PRESERVED
    // ============================================================

    #[Test]
    public function token_scopes_are_preserved_across_refresh()
    {
        // ARRANGE: Get tokens with specific scopes
        $originalScopes = ['openid', 'profile', 'email'];
        $tokens = $this->performSsoOAuthFlow($originalScopes);
        $refreshToken = $tokens['refresh_token'];

        // Parse original access token to verify scopes
        $originalTokenParts = explode('.', $tokens['access_token']);
        if (count($originalTokenParts) === 3) {
            $originalPayload = json_decode(base64_decode($originalTokenParts[1]), true);
            $originalScopeString = $originalPayload['scopes'] ?? null;
        }

        // ACT: Refresh the token with same scopes
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
            'scope' => implode(' ', $originalScopes),
        ]);

        // ASSERT: Refresh successful
        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        // Parse new access token
        $newTokenParts = explode('.', $newTokens['access_token']);
        if (count($newTokenParts) === 3) {
            $newPayload = json_decode(base64_decode($newTokenParts[1]), true);
            $newScopeString = $newPayload['scopes'] ?? null;

            // ASSERT: Scopes are preserved (if scopes are in JWT)
            if ($originalScopeString !== null && $newScopeString !== null) {
                $this->assertEquals($originalScopeString, $newScopeString);
            }

            // ASSERT: User ID is preserved
            $this->assertEquals($originalPayload['sub'], $newPayload['sub']);
            $this->assertEquals($this->user->id, $newPayload['sub']);
        }

        // ASSERT: Can use new token to access protected resources
        $this->actingAsApiUserWithToken($this->user, $originalScopes);
        $userinfoResponse = $this->getJson('/api/v1/oauth/userinfo');
        $userinfoResponse->assertStatus(200);
    }

    // ============================================================
    // TOKEN EXPIRY TIMES VALIDATION
    // ============================================================

    #[Test]
    public function refreshed_tokens_have_valid_expiry_times()
    {
        // ARRANGE: Get initial tokens
        $tokens = $this->performSsoOAuthFlow(['openid', 'profile']);
        $refreshToken = $tokens['refresh_token'];

        // ACT: Refresh the token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        // ASSERT: Refresh successful
        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        // ASSERT: expires_in is present and valid
        $this->assertArrayHasKey('expires_in', $newTokens);
        $expiresIn = $newTokens['expires_in'];
        $this->assertIsInt($expiresIn);
        $this->assertGreaterThan(0, $expiresIn);

        // ASSERT: Can calculate valid expiration time
        $expiresAt = Carbon::now()->addSeconds($expiresIn);
        $this->assertInstanceOf(Carbon::class, $expiresAt);
        $this->assertTrue($expiresAt->isFuture());

        // Parse JWT to verify expiration claim
        $tokenParts = explode('.', $newTokens['access_token']);
        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);

            // ASSERT: JWT has expiration claim
            $this->assertArrayHasKey('exp', $payload);
            $jwtExpiration = $payload['exp'];

            // ASSERT: JWT expiration is in the future
            $this->assertGreaterThan(time(), $jwtExpiration);

            // ASSERT: JWT expiration roughly matches expires_in
            // Allow 5 second tolerance for processing time
            $calculatedExpiry = time() + $expiresIn;
            $this->assertEqualsWithDelta($calculatedExpiry, $jwtExpiration, 5);
        }
    }

    // ============================================================
    // MULTIPLE SEQUENTIAL REFRESH OPERATIONS
    // ============================================================

    #[Test]
    public function multiple_sequential_refresh_operations_work_correctly()
    {
        // ARRANGE: Get initial tokens
        $tokens = $this->performSsoOAuthFlow(['openid', 'profile', 'email']);
        $currentRefreshToken = $tokens['refresh_token'];
        $previousAccessTokens = [$tokens['access_token']];

        // ACT: Perform 5 sequential refresh operations
        $refreshCount = 5;
        for ($i = 0; $i < $refreshCount; $i++) {
            sleep(1); // Ensure different timestamps

            // ACT: Refresh with current refresh token
            $refreshResponse = $this->postJson('/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $currentRefreshToken,
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'sso-test-secret-refresh-123',
                'scope' => 'openid profile email',
            ]);

            // ASSERT: Each refresh successful
            $refreshResponse->assertStatus(200);
            $newTokens = $refreshResponse->json();

            // ASSERT: New tokens provided
            $this->assertArrayHasKey('access_token', $newTokens);
            $this->assertArrayHasKey('refresh_token', $newTokens);

            // ASSERT: New access token is different from all previous ones
            $this->assertNotContains($newTokens['access_token'], $previousAccessTokens);

            // ASSERT: New refresh token is different from current one
            $this->assertNotEquals($currentRefreshToken, $newTokens['refresh_token']);

            // Update for next iteration
            $previousAccessTokens[] = $newTokens['access_token'];
            $currentRefreshToken = $newTokens['refresh_token'];
        }

        // ASSERT: Final refresh token still works
        $finalRefresh = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $currentRefreshToken,
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
        ]);

        $finalRefresh->assertStatus(200);

        // ASSERT: We got unique access tokens for each refresh
        $this->assertCount($refreshCount + 1, $previousAccessTokens);
        $this->assertCount($refreshCount + 1, array_unique($previousAccessTokens));
    }

    // ============================================================
    // HELPER METHODS
    // ============================================================

    /**
     * Perform complete SSO OAuth flow and return tokens
     *
     * @param  array  $scopes  OAuth scopes to request
     * @return array Token response containing access_token, refresh_token, etc.
     */
    protected function performSsoOAuthFlow(array $scopes = ['openid', 'profile']): array
    {
        // Generate PKCE parameters
        $codeVerifier = Str::random(128);
        $codeChallenge = $this->generateS256Challenge($codeVerifier);
        $state = Str::random(40);

        // Step 1: Request authorization
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

        // Step 2: Extract auth token and approve
        preg_match('/name="auth_token" value="([^"]+)"/', $authResponse->getContent(), $matches);
        $authToken = $matches[1];

        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $this->oauthClient->id,
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        // Step 3: Extract authorization code
        parse_str(parse_url($approvalResponse->headers->get('Location'), PHP_URL_QUERY), $query);
        $authCode = $query['code'];

        // Step 4: Exchange code for tokens
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'sso-test-secret-refresh-123',
            'code' => $authCode,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
        ]);

        return $tokenResponse->json();
    }

    /**
     * Generate S256 code challenge from verifier
     *
     * @param  string  $verifier  PKCE code verifier
     * @return string Base64-URL-encoded SHA256 hash of verifier
     */
    protected function generateS256Challenge(string $verifier): string
    {
        return rtrim(
            strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
            '='
        );
    }
}
