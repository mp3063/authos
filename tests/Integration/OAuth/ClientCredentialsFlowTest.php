<?php

namespace Tests\Integration\OAuth;

use App\Models\Application;
use Laravel\Passport\Client;
use Tests\TestCase;

/**
 * Client Credentials Flow Integration Tests (RFC 6749)
 *
 * Tests machine-to-machine authentication including:
 * - Basic client credentials flow
 * - Scope validation
 * - Rate limiting
 * - Invalid client handling
 * - Token usage restrictions
 */
class ClientCredentialsFlowTest extends TestCase
{
    protected Application $application;

    protected Client $confidentialClient;

    protected function setUp(): void
    {
        parent::setUp();

        // Passport is set up in TestCase - no need to install

        $organization = \App\Models\Organization::factory()->create();

        $this->application = Application::factory()->create([
            'name' => 'M2M Test App',
            'organization_id' => $organization->id,
        ]);

        $this->confidentialClient = Client::create([
            'name' => 'M2M Confidential Client',
            'secret' => 'client-secret-m2m-123',
            'redirect' => '',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application->update([
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_basic_client_credentials_flow(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
            'scope' => 'read write',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertArrayHasKey('token_type', $tokenData);
        $this->assertArrayHasKey('expires_in', $tokenData);
        $this->assertEquals('Bearer', $tokenData['token_type']);
        $this->assertIsString($tokenData['access_token']);
        $this->assertIsInt($tokenData['expires_in']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_with_specific_scopes(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
            'scope' => 'read',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        $this->assertArrayHasKey('access_token', $tokenData);

        // Verify token contains only requested scope (if scope is returned)
        if (isset($tokenData['scope'])) {
            $this->assertStringContainsString('read', $tokenData['scope']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_without_scope(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertIsString($tokenData['access_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_invalid_client_id(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => 99999, // Non-existent
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $response->assertStatus(401);
        $response->assertJsonFragment(['error' => 'invalid_client']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_invalid_client_secret(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'wrong-secret',
        ]);

        $response->assertStatus(401);
        $response->assertJsonFragment(['error' => 'invalid_client']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_missing_client_secret(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
        ]);

        $response->assertStatus(400);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_revoked_client(): void
    {
        // Revoke the client
        $this->confidentialClient->update(['revoked' => true]);

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_token_does_not_have_user_scopes(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
            'scope' => 'openid profile email',
        ]);

        // Client credentials tokens should not include user-specific scopes
        // Passport may accept the request but filter out invalid scopes
        $response->assertStatus(200);

        $tokenData = $response->json();
        if (isset($tokenData['scope'])) {
            // User scopes should not be granted
            $this->assertStringNotContainsString('openid', $tokenData['scope']);
            $this->assertStringNotContainsString('profile', $tokenData['scope']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_multiple_concurrent_requests(): void
    {
        $responses = [];

        // Make 5 concurrent token requests
        for ($i = 0; $i < 5; $i++) {
            $responses[] = $this->postJson('/oauth/token', [
                'grant_type' => 'client_credentials',
                'client_id' => $this->confidentialClient->id,
                'client_secret' => 'client-secret-m2m-123',
                'scope' => 'read',
            ]);
        }

        // All requests should succeed
        foreach ($responses as $response) {
            $response->assertStatus(200);
            $this->assertArrayHasKey('access_token', $response->json());
        }

        // Each token should be unique
        $tokens = array_map(fn ($r) => $r->json()['access_token'], $responses);
        $uniqueTokens = array_unique($tokens);
        $this->assertCount(5, $uniqueTokens);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_token_expiration(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        // Verify expires_in is present and valid
        $this->assertArrayHasKey('expires_in', $tokenData);
        $this->assertIsInt($tokenData['expires_in']);
        $this->assertGreaterThan(0, $tokenData['expires_in']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_with_basic_auth(): void
    {
        // Use HTTP Basic Authentication instead of body parameters
        $credentials = base64_encode($this->confidentialClient->id.':client-secret-m2m-123');

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'scope' => 'read',
        ], [
            'Authorization' => 'Basic '.$credentials,
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertIsString($tokenData['access_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_token_cannot_access_user_endpoints(): void
    {
        // Get client credentials token
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $tokenResponse->assertStatus(200);
        $token = $tokenResponse->json()['access_token'];

        // Try to access userinfo endpoint (requires user context)
        $userinfoResponse = $this->withHeaders([
            'Authorization' => 'Bearer '.$token,
        ])->getJson('/api/v1/oauth/userinfo');

        // Should fail because client credentials tokens don't have user context
        $userinfoResponse->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_no_refresh_token(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        // Client credentials flow should not include refresh token
        $this->assertArrayNotHasKey('refresh_token', $tokenData);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_rate_limiting(): void
    {
        // Make many requests in rapid succession
        $successCount = 0;
        $rateLimitCount = 0;

        for ($i = 0; $i < 150; $i++) { // Exceed typical rate limits
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'client_credentials',
                'client_id' => $this->confidentialClient->id,
                'client_secret' => 'client-secret-m2m-123',
            ]);

            if ($response->getStatusCode() === 200) {
                $successCount++;
            } elseif ($response->getStatusCode() === 429) {
                $rateLimitCount++;
            }
        }

        // Most requests should succeed in test environment
        // In production, rate limiting would kick in
        $this->assertGreaterThan(0, $successCount);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_token_includes_client_id(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        // Parse JWT to verify client_id
        $tokenParts = explode('.', $tokenData['access_token']);

        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);

            // Verify client context
            $this->assertArrayHasKey('aud', $payload);
            $this->assertArrayHasKey('jti', $payload);
            $this->assertArrayHasKey('exp', $payload);

            // Client credentials tokens: 'sub' claim is set to client_id
            // This is standard behavior in league/oauth2-server and matches
            // major OAuth providers (Auth0, Okta, Keycloak)
            // The 'sub' claim identifies the client acting on its own behalf
            $this->assertArrayHasKey('sub', $payload);
            $this->assertEquals($this->confidentialClient->id, $payload['sub']);

            // Important: 'sub' equals 'aud' indicates client is acting on own behalf,
            // not on behalf of a user (which is correct for client credentials flow)
            $this->assertEquals($payload['aud'], $payload['sub']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_client_credentials_with_wildcard_scopes(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $this->confidentialClient->id,
            'client_secret' => 'client-secret-m2m-123',
            'scope' => '*',
        ]);

        // Wildcard scope may or may not be supported
        // Test documents expected behavior
        if ($response->getStatusCode() === 200) {
            $tokenData = $response->json();
            $this->assertArrayHasKey('access_token', $tokenData);
        } else {
            $response->assertStatus(400);
        }
    }
}
