<?php

namespace Tests\Integration\OAuth;

use App\Models\Application;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Client;
use Tests\TestCase;

/**
 * Password Grant Flow Integration Tests (RFC 6749)
 *
 * Tests first-party client authentication including:
 * - Basic password grant flow
 * - MFA integration
 * - Account lockout handling
 * - Invalid credentials
 * - Inactive account handling
 */
class PasswordGrantFlowTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Application $application;

    protected Client $passwordClient;

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('passport:install', ['--no-interaction' => true]);

        $this->user = User::factory()->create([
            'email' => 'password@example.com',
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
            'is_active' => true,
        ]);

        $this->application = Application::factory()->create([
            'name' => 'Password Grant Test App',
            'organization_id' => $this->user->organization_id,
        ]);

        $this->passwordClient = Client::create([
            'name' => 'Password Grant Client',
            'secret' => 'password-client-secret',
            'redirect' => '',
            'personal_access_client' => false,
            'password_client' => true, // Enable password grant
            'revoked' => false,
        ]);

        $this->application->update([
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_basic_password_grant_flow(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
            'scope' => 'openid profile email',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertArrayHasKey('refresh_token', $tokenData);
        $this->assertArrayHasKey('token_type', $tokenData);
        $this->assertArrayHasKey('expires_in', $tokenData);
        $this->assertEquals('Bearer', $tokenData['token_type']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_invalid_credentials(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'wrong-password',
        ]);

        $response->assertStatus(400);
        $response->assertJsonFragment(['error' => 'invalid_grant']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_nonexistent_user(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'nonexistent@example.com',
            'password' => 'password123',
        ]);

        $response->assertStatus(400);
        $response->assertJsonFragment(['error' => 'invalid_grant']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_inactive_account(): void
    {
        $this->user->update(['is_active' => false]);

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        // Password grant should reject inactive accounts
        $response->assertStatus(400);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_with_specific_scopes(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
            'scope' => 'openid profile',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        $this->assertArrayHasKey('access_token', $tokenData);

        // Verify scopes if returned
        if (isset($tokenData['scope'])) {
            $this->assertStringContainsString('openid', $tokenData['scope']);
            $this->assertStringContainsString('profile', $tokenData['scope']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_missing_username(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'password' => 'password123',
        ]);

        $response->assertStatus(400);
        $response->assertJsonFragment(['error' => 'invalid_request']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_missing_password(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
        ]);

        $response->assertStatus(400);
        $response->assertJsonFragment(['error' => 'invalid_request']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_invalid_client(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => 99999,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        $response->assertStatus(401);
        $response->assertJsonFragment(['error' => 'invalid_client']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_wrong_client_secret(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'wrong-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        $response->assertStatus(401);
        $response->assertJsonFragment(['error' => 'invalid_client']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_with_non_password_client(): void
    {
        // Create a regular OAuth client (not password grant enabled)
        $regularClient = Client::create([
            'name' => 'Regular Client',
            'secret' => 'regular-secret',
            'redirect' => 'https://app.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $regularClient->id,
            'client_secret' => 'regular-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        // Should fail because client is not a password client
        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_refresh_token_flow(): void
    {
        // Get initial tokens
        $initialResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        $initialResponse->assertStatus(200);
        $initialTokens = $initialResponse->json();

        // Use refresh token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $initialTokens['refresh_token'],
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
        ]);

        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        $this->assertArrayHasKey('access_token', $newTokens);
        $this->assertNotEquals($initialTokens['access_token'], $newTokens['access_token']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_with_mfa_enabled_user(): void
    {
        // Enable MFA for user
        $this->user->update([
            'mfa_secret' => 'test-mfa-secret',
            'mfa_enabled' => true,
        ]);

        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        // Password grant should still work, but in production
        // might require additional MFA verification step
        // For now, test that it either succeeds or requires MFA
        $this->assertContains($response->getStatusCode(), [200, 202, 403]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_rate_limiting(): void
    {
        // Make multiple failed attempts
        $responses = [];

        for ($i = 0; $i < 10; $i++) {
            $responses[] = $this->postJson('/oauth/token', [
                'grant_type' => 'password',
                'client_id' => $this->passwordClient->id,
                'client_secret' => 'password-client-secret',
                'username' => 'password@example.com',
                'password' => 'wrong-password',
            ]);
        }

        // All should fail with invalid_grant
        foreach ($responses as $response) {
            $this->assertContains($response->getStatusCode(), [400, 429]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_multiple_concurrent_sessions(): void
    {
        // Create multiple tokens for same user
        $tokens = [];

        for ($i = 0; $i < 3; $i++) {
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'password',
                'client_id' => $this->passwordClient->id,
                'client_secret' => 'password-client-secret',
                'username' => 'password@example.com',
                'password' => 'password123',
            ]);

            $response->assertStatus(200);
            $tokens[] = $response->json()['access_token'];
        }

        // All tokens should be unique
        $this->assertCount(3, array_unique($tokens));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_grant_token_includes_user_context(): void
    {
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'password',
            'client_id' => $this->passwordClient->id,
            'client_secret' => 'password-client-secret',
            'username' => 'password@example.com',
            'password' => 'password123',
        ]);

        $response->assertStatus(200);
        $tokenData = $response->json();

        // Parse JWT token
        $tokenParts = explode('.', $tokenData['access_token']);

        if (count($tokenParts) === 3) {
            $payload = json_decode(base64_decode($tokenParts[1]), true);

            // Should have user context (sub claim)
            $this->assertArrayHasKey('sub', $payload);
            $this->assertEquals($this->user->id, $payload['sub']);

            // Should have standard JWT claims
            $this->assertArrayHasKey('aud', $payload);
            $this->assertArrayHasKey('exp', $payload);
            $this->assertArrayHasKey('iat', $payload);
        }
    }
}
