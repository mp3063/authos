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

        // Step 1: Authorization request with PKCE - authenticate first
        $this->actingAs($user, 'web'); // Authenticate user for web guard
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

        // Extract the auth token from the authorization form
        $authContent = $authResponse->getContent();
        preg_match('/name="auth_token" value="([^"]+)"/', $authContent, $matches);
        $authToken = $matches[1] ?? null;

        $this->assertNotNull($authToken, 'Could not extract auth_token from authorization response');

        // Step 2: User approves authorization (simulate approval)
        // In a real flow, user would click approve, but we simulate the redirect
        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $authParams['state'],
            'client_id' => $authParams['client_id'],
            'auth_token' => $authToken,
            'approve' => '1', // Simulate user approval
        ]);

        $approvalResponse->assertRedirect();
        $redirectUrl = $approvalResponse->headers->get('Location');

        // Extract authorization code
        parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $queryParams);
        $authCode = $queryParams['code'];

        // Step 3: Token exchange with correct code verifier - use Passport endpoint
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->plainSecret ?? $this->oauthClient->secret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $codeVerifier,
        ]);

        // Debug token response if it fails
        if ($tokenResponse->getStatusCode() !== 200) {
            dump('Token Response Status: '.$tokenResponse->getStatusCode());
            dump('Token Response Content: '.$tokenResponse->getContent());
            dump('Client ID: '.$this->oauthClient->id);
            dump('Client Secret: '.($this->oauthClient->plainSecret ?? $this->oauthClient->secret));
            dump('Auth Code: '.$authCode);
        }

        $tokenResponse->assertStatus(200);
        $tokenData = $tokenResponse->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertArrayHasKey('refresh_token', $tokenData);

        // Step 4: Verify PKCE prevents code injection
        $wrongCodeVerifier = $this->generateCodeVerifier();

        $invalidTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->plainSecret ?? $this->oauthClient->secret,
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
        $this->assertArrayHasKey('access_token', $initialTokens);
        $this->assertArrayHasKey('refresh_token', $initialTokens);

        // Use refresh token to get new tokens
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $initialTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->plainSecret ?? $this->oauthClient->secret,
        ]);

        if ($refreshResponse->getStatusCode() !== 200) {
            dump('Refresh token error:', $refreshResponse->json());
        }
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
            'client_secret' => $this->oauthClient->plainSecret ?? $this->oauthClient->secret,
        ]);

        $oldRefreshResponse->assertStatus(400); // Passport returns 400 for invalid refresh tokens

        // Verify new refresh token works
        $secondRefreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $newTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->plainSecret ?? $this->oauthClient->secret,
        ]);

        $secondRefreshResponse->assertStatus(200);
    }

    /**
     * Test scope-based access control
     */
    public function test_scope_based_access_control(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Create token with limited scopes
        $limitedScopeTokens = $this->performOAuthFlow($user, $this->oauthClient, ['openid', 'profile']);
        $this->assertArrayHasKey('access_token', $limitedScopeTokens);

        // Test access to profile endpoint (should work with profile scope)
        $profileResponse = $this->getJson('/api/v1/oauth/userinfo', [
            'Authorization' => 'Bearer '.$limitedScopeTokens['access_token'],
        ]);
        $profileResponse->assertStatus(200);

        // Create token with broader scopes
        $fullScopeTokens = $this->performOAuthFlow($user, $this->oauthClient, ['openid', 'profile', 'email', 'read', 'write']);
        $this->assertArrayHasKey('access_token', $fullScopeTokens);

        // Test access with full scopes
        $fullAccessResponse = $this->getJson('/api/v1/oauth/userinfo', [
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
        $this->assertArrayHasKey('access_token', $firstOrgTokens);

        // Attempt to use first org user to access second org's app should fail context check
        $this->actingAs($firstOrgUser, 'api');
        $response = $this->getJson('/api/v1/applications/'.$secondOrgApp->id);
        $response->assertStatus(404); // Should not see other org's app

        // Test 2: Verify proper organization isolation in OAuth flows
        $this->actingAs($secondOrgUser, 'api');
        $secondOrgTokens = $this->performOAuthFlow($secondOrgUser, $secondOrgClient);
        $this->assertArrayHasKey('access_token', $secondOrgTokens);

        // Use second org token to access userinfo
        $secondOrgUserInfo = $this->getJson('/api/v1/oauth/userinfo', [
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
        $clientSecret = $this->oauthClient->plainSecret ?? $this->oauthClient->secret;

        // Test 1: Authorization code replay attack
        $authCode = $this->getAuthorizationCode($user, $this->oauthClient);

        // First use should succeed
        $firstTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $clientSecret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $this->testCodeVerifier,
        ]);

        $firstTokenResponse->assertStatus(200);

        // Second use should fail (code already used)
        $replayTokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $clientSecret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $this->testCodeVerifier,
        ]);

        $replayTokenResponse->assertStatus(400);

        // Test 2: Invalid redirect URI attack
        $invalidRedirectResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $clientSecret,
            'code' => $this->createAuthorizationCode($user, $this->oauthClient),
            'redirect_uri' => 'https://malicious-site.com/callback',
            'code_verifier' => $this->testCodeVerifier,
        ]);

        $invalidRedirectResponse->assertStatus(400);

        // Test 3: Client credential stuffing attack
        $wrongClientResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => 'wrong_secret',
            'code' => $this->createAuthorizationCode($user, $this->oauthClient),
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $this->testCodeVerifier,
        ]);

        $wrongClientResponse->assertStatus(401);

        // Test 4: Expired authorization code
        $expiredCode = 'expired_code_'.uniqid();
        DB::table('oauth_auth_codes')->insert([
            'id' => $expiredCode,
            'user_id' => $user->id,
            'client_id' => $this->oauthClient->id,
            'scopes' => 'openid profile', // Space-separated string, not JSON
            'revoked' => false,
            'expires_at' => now()->subMinutes(5), // Definitely expired
        ]);

        $expiredCodeResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $clientSecret,
            'code' => $expiredCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => $this->testCodeVerifier,
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
        for ($i = 0; $i < 65; $i++) { // Increase to 65 to exceed Laravel's default limit of 60
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'authorization_code',
                'client_id' => $this->oauthClient->id,
                'client_secret' => 'wrong_secret', // Will fail but trigger rate limit
                'code' => 'invalid_code',
                'redirect_uri' => $this->oauthClient->redirect,
            ]);

            $rateLimitResponses[] = $response->getStatusCode();

            if ($response->getStatusCode() === 429) {
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
        $discoveryResponse = $this->getJson('/api/.well-known/openid-configuration');

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
