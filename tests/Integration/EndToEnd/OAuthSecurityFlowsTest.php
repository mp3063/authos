<?php

namespace Tests\Integration\EndToEnd;

use App\Models\Application;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Client;

/**
 * End-to-End tests for OAuth security flows and edge cases.
 *
 * Tests comprehensive OAuth 2.0 security scenarios including PKCE,
 * token rotation, introspection, and various attack vectors.
 */
class OAuthSecurityFlowsTest extends EndToEndTestCase
{
    /**
     * Test PKCE (Proof Key for Code Exchange) flow
     */
    public function test_pkce_authorization_code_flow(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Generate PKCE parameters
        $codeVerifier = $this->generateCodeVerifier();
        $codeChallenge = $this->generateCodeChallenge($codeVerifier);

        // Step 1: Authorization request with PKCE
        $authParams = [
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->oauthClient->redirect,
            'scope' => 'openid profile email',
            'state' => 'secure_state_'.uniqid(),
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        $authResponse = $this->get('/oauth/authorize?'.http_build_query($authParams));
        $authResponse->assertStatus(200);

        // Step 2: User approves authorization
        $approvalResponse = $this->post('/oauth/authorize', array_merge($authParams, [
            'approve' => 'Approve',
        ]));

        $approvalResponse->assertRedirect();
        $redirectUrl = $approvalResponse->headers->get('Location');

        // Extract authorization code
        parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $queryParams);
        $authCode = $queryParams['code'];

        // Step 3: Token exchange with correct code verifier
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $codeVerifier,
        ]);

        $tokenResponse->assertStatus(200);
        $tokenData = $tokenResponse->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertArrayHasKey('refresh_token', $tokenData);

        // Step 4: Verify PKCE prevents code injection
        $wrongCodeVerifier = $this->generateCodeVerifier();

        $invalidTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $this->createAuthorizationCode($user, $this->oauthClient),
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $wrongCodeVerifier,
        ]);

        $invalidTokenResponse->assertStatus(400);
    }

    /**
     * Test refresh token rotation security
     */
    public function test_refresh_token_rotation(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Get initial tokens
        $initialTokens = $this->performOAuthFlow($user, $this->oauthClient);

        // Use refresh token to get new tokens
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $initialTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
        ]);

        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        // Verify new tokens are different
        $this->assertNotEquals($initialTokens['access_token'], $newTokens['access_token']);
        $this->assertNotEquals($initialTokens['refresh_token'], $newTokens['refresh_token']);

        // Verify old refresh token is invalidated
        $oldRefreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $initialTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
        ]);

        $oldRefreshResponse->assertStatus(401);

        // Verify new refresh token works
        $secondRefreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $newTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
        ]);

        $secondRefreshResponse->assertStatus(200);
    }

    /**
     * Test token introspection endpoint security
     */
    public function test_token_introspection_security(): void
    {
        $user = $this->actingAsTestUser('regular');
        $tokens = $this->performOAuthFlow($user, $this->oauthClient);

        // Step 1: Valid token introspection
        $introspectResponse = $this->postJson('/oauth/introspect', [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'access_token',
        ], [
            'Authorization' => 'Basic '.base64_encode($this->oauthClient->id.':'.$this->oauthClient->secret),
        ]);

        $introspectResponse->assertStatus(200);
        $introspectionData = $introspectResponse->json();

        $this->assertTrue($introspectionData['active']);
        $this->assertEquals($user->id, $introspectionData['sub']);
        $this->assertArrayHasKey('scope', $introspectionData);
        $this->assertArrayHasKey('exp', $introspectionData);

        // Step 2: Invalid token introspection
        $invalidIntrospectResponse = $this->postJson('/oauth/introspect', [
            'token' => 'invalid_token_123',
            'token_type_hint' => 'access_token',
        ], [
            'Authorization' => 'Basic '.base64_encode($this->oauthClient->id.':'.$this->oauthClient->secret),
        ]);

        $invalidIntrospectResponse->assertStatus(200);
        $invalidData = $invalidIntrospectResponse->json();
        $this->assertFalse($invalidData['active']);

        // Step 3: Introspection without client authentication
        $unauthenticatedResponse = $this->postJson('/oauth/introspect', [
            'token' => $tokens['access_token'],
        ]);

        $unauthenticatedResponse->assertStatus(401);

        // Step 4: Revoke token and verify introspection shows inactive
        $this->postJson('/oauth/token/revoke', [
            'token' => $tokens['access_token'],
        ], [
            'Authorization' => 'Basic '.base64_encode($this->oauthClient->id.':'.$this->oauthClient->secret),
        ]);

        $revokedIntrospectResponse = $this->postJson('/oauth/introspect', [
            'token' => $tokens['access_token'],
        ], [
            'Authorization' => 'Basic '.base64_encode($this->oauthClient->id.':'.$this->oauthClient->secret),
        ]);

        $revokedIntrospectResponse->assertStatus(200);
        $revokedData = $revokedIntrospectResponse->json();
        $this->assertFalse($revokedData['active']);
    }

    /**
     * Test scope-based access control
     */
    public function test_scope_based_access_control(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Create token with limited scopes
        $limitedScopeTokens = $this->performOAuthFlow($user, $this->oauthClient, ['openid', 'profile']);

        // Test access to profile endpoint (should work with profile scope)
        $profileResponse = $this->getJson('/oauth/userinfo', [
            'Authorization' => 'Bearer '.$limitedScopeTokens['access_token'],
        ]);
        $profileResponse->assertStatus(200);

        // Create token with broader scopes
        $fullScopeTokens = $this->performOAuthFlow($user, $this->oauthClient, ['openid', 'profile', 'email', 'read', 'write']);

        // Test access with full scopes
        $fullAccessResponse = $this->getJson('/oauth/userinfo', [
            'Authorization' => 'Bearer '.$fullScopeTokens['access_token'],
        ]);
        $fullAccessResponse->assertStatus(200);

        // Verify scope information in userinfo response
        $userInfo = $fullAccessResponse->json();
        $this->assertArrayHasKey('email', $userInfo);
        $this->assertArrayHasKey('name', $userInfo);
    }

    /**
     * Test cross-organization OAuth security
     */
    public function test_cross_organization_oauth_security(): void
    {
        // Create second organization with its own application
        $secondOrg = $this->createOrganization([
            'name' => 'Second Organization',
            'slug' => 'second-org',
        ]);

        $secondOrgUser = $this->createUser([
            'name' => 'Second Org User',
            'email' => 'user@secondorg.com',
            'organization_id' => $secondOrg->id,
        ], 'User');

        $secondOrgApp = Application::factory()->create([
            'name' => 'Second Org App',
            'organization_id' => $secondOrg->id,
        ]);

        $secondOrgClient = Client::create([
            'name' => 'Second Org Client',
            'secret' => 'second_org_secret',
            'redirect' => 'https://secondorg.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        // Test 1: User from first org cannot access second org's application resources
        $firstOrgUser = $this->actingAsTestUser('regular');
        $firstOrgTokens = $this->performOAuthFlow($firstOrgUser, $this->oauthClient);

        // Attempt to use first org token with second org client should fail context check
        $this->actingAs($secondOrgUser, 'api');
        $response = $this->getJson('/api/v1/applications/'.$secondOrgApp->id);
        $response->assertStatus(404); // Should not see other org's app

        // Test 2: Verify proper organization isolation in OAuth flows
        $this->actingAs($secondOrgUser, 'api');
        $secondOrgTokens = $this->performOAuthFlow($secondOrgUser, $secondOrgClient);

        // Use second org token to access userinfo
        $secondOrgUserInfo = $this->getJson('/oauth/userinfo', [
            'Authorization' => 'Bearer '.$secondOrgTokens['access_token'],
        ]);

        $secondOrgUserInfo->assertStatus(200);
        $userInfo = $secondOrgUserInfo->json();
        $this->assertEquals($secondOrgUser->id, $userInfo['sub']);
        $this->assertEquals($secondOrg->id, $userInfo['organization_id']);
    }

    /**
     * Test OAuth security against common attack vectors
     */
    public function test_oauth_security_against_attacks(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Test 1: Authorization code replay attack
        $authCode = $this->createAuthorizationCode($user, $this->oauthClient);

        // First use should succeed
        $firstTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => 'test_verifier',
        ]);

        $firstTokenResponse->assertStatus(200);

        // Second use should fail (code already used)
        $replayTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => 'test_verifier',
        ]);

        $replayTokenResponse->assertStatus(400);

        // Test 2: Invalid redirect URI attack
        $invalidRedirectResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $this->createAuthorizationCode($user, $this->oauthClient),
            'redirect_uri' => 'https://malicious-site.com/callback',
            'code_verifier' => 'test_verifier',
        ]);

        $invalidRedirectResponse->assertStatus(400);

        // Test 3: Client credential stuffing attack
        $wrongClientResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'wrong_secret',
            'code' => $this->createAuthorizationCode($user, $this->oauthClient),
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => 'test_verifier',
        ]);

        $wrongClientResponse->assertStatus(401);

        // Test 4: Expired authorization code
        $expiredCode = 'expired_code_'.uniqid();
        DB::table('oauth_authorization_codes')->insert([
            'id' => $expiredCode,
            'user_id' => $user->id,
            'client_id' => $this->oauthClient->id,
            'scopes' => json_encode(['openid', 'profile']),
            'revoked' => false,
            'created_at' => now()->subMinutes(15), // Expired
            'updated_at' => now()->subMinutes(15),
            'expires_at' => now()->subMinutes(5), // Definitely expired
            'code_challenge' => 'test_challenge',
            'code_challenge_method' => 'S256',
        ]);

        $expiredCodeResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $expiredCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => 'test_verifier',
        ]);

        $expiredCodeResponse->assertStatus(400);
    }

    /**
     * Test rate limiting on OAuth endpoints
     */
    public function test_oauth_rate_limiting(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Test rate limiting on token endpoint
        $rateLimitResponses = [];
        for ($i = 0; $i < 15; $i++) {
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'authorization_code',
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'wrong_secret', // Will fail but trigger rate limit
                'code' => 'invalid_code',
                'redirect_uri' => $this->oauthClient->redirect,
            ]);

            $rateLimitResponses[] = $response->status();

            if ($response->status() === 429) {
                break; // Hit rate limit
            }
        }

        // Should eventually hit rate limit
        $this->assertContains(429, $rateLimitResponses);
    }

    /**
     * Test OpenID Connect discovery endpoint
     */
    public function test_openid_connect_discovery(): void
    {
        $discoveryResponse = $this->getJson('/.well-known/openid-configuration');

        $discoveryResponse->assertStatus(200);
        $discoveryData = $discoveryResponse->json();

        // Verify required OpenID Connect discovery fields
        $this->assertArrayHasKey('issuer', $discoveryData);
        $this->assertArrayHasKey('authorization_endpoint', $discoveryData);
        $this->assertArrayHasKey('token_endpoint', $discoveryData);
        $this->assertArrayHasKey('userinfo_endpoint', $discoveryData);
        $this->assertArrayHasKey('jwks_uri', $discoveryData);
        $this->assertArrayHasKey('response_types_supported', $discoveryData);
        $this->assertArrayHasKey('subject_types_supported', $discoveryData);
        $this->assertArrayHasKey('id_token_signing_alg_values_supported', $discoveryData);

        // Verify proper URLs
        $this->assertStringEndsWith('/oauth/authorize', $discoveryData['authorization_endpoint']);
        $this->assertStringEndsWith('/oauth/token', $discoveryData['token_endpoint']);
        $this->assertStringEndsWith('/oauth/userinfo', $discoveryData['userinfo_endpoint']);

        // Verify supported response types
        $this->assertContains('code', $discoveryData['response_types_supported']);
        $this->assertContains('token', $discoveryData['response_types_supported']);
    }

    /**
     * Generate a secure code verifier for PKCE
     */
    private function generateCodeVerifier(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Generate code challenge from verifier for PKCE
     */
    private function generateCodeChallenge(string $codeVerifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
    }
}
