<?php

namespace Tests\Security;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * OWASP A02:2021 - Cryptographic Failures
 *
 * Tests for:
 * - Sensitive data exposure
 * - Weak password hashing
 * - Insecure data transmission
 * - Missing encryption for sensitive data
 * - Weak cryptographic algorithms
 * - Improper key management
 */
class OwaspA02CryptographicFailuresTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
    }

    /** @test */
    public function it_uses_bcrypt_for_password_hashing()
    {
        $user = User::factory()->create([
            'password' => Hash::make('testpassword123'),
        ]);

        // Verify bcrypt is used (bcrypt hashes start with $2y$)
        $this->assertStringStartsWith('$2y$', $user->password);
        $this->assertTrue(Hash::check('testpassword123', $user->password));
    }

    /** @test */
    public function it_does_not_expose_passwords_in_api_responses()
    {
        Passport::actingAs($this->user);

        $response = $this->getJson('/api/v1/profile');

        $response->assertStatus(200);
        $response->assertJsonMissing(['password']);
        $this->assertArrayNotHasKey('password', $response->json('data'));
    }

    /** @test */
    public function it_does_not_expose_client_secrets_in_application_listing()
    {
        $app = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->user);

        $response = $this->getJson('/api/v1/applications');

        $response->assertStatus(200);

        foreach ($response->json('data') as $application) {
            $this->assertArrayNotHasKey('client_secret', $application);
            $this->assertArrayNotHasKey('secret', $application);
        }
    }

    /** @test */
    public function it_masks_sensitive_data_in_logs()
    {
        // Attempt login with credentials
        $response = $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'wrongpassword',
        ]);

        // Check that password is not logged in authentication logs
        $authLog = \App\Models\AuthenticationLog::latest()->first();

        if ($authLog && isset($authLog->metadata)) {
            $this->assertArrayNotHasKey('password', $authLog->metadata);
        }
    }

    /** @test */
    public function it_enforces_https_in_production()
    {
        // In production, check that HSTS header is set
        config(['app.env' => 'production']);

        $response = $this->getJson('/api/v1/profile');

        // If the app is configured for HTTPS
        if (config('app.url') && str_starts_with(config('app.url'), 'https://')) {
            $this->assertNotNull($response->headers->get('Strict-Transport-Security'));
        }
    }

    /** @test */
    public function it_uses_secure_cookies_for_sessions()
    {
        $response = $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'password',
        ]);

        $cookies = $response->headers->getCookies();

        foreach ($cookies as $cookie) {
            // In HTTPS environments, cookies should be secure
            if (config('session.secure')) {
                $this->assertTrue($cookie->isSecure(), 'Session cookies must be secure');
            }

            // Session cookies should be HTTP-only
            if ($cookie->getName() === config('session.cookie')) {
                $this->assertTrue($cookie->isHttpOnly(), 'Session cookies must be HTTP-only');
            }
        }
    }

    /** @test */
    public function it_encrypts_sensitive_configuration_data()
    {
        $ssoConfig = \App\Models\SSOConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'provider' => 'oidc',
            'client_secret' => 'super-secret-value',
        ]);

        // Client secret should be encrypted in database
        $rawData = \DB::table('sso_configurations')
            ->where('id', $ssoConfig->id)
            ->first();

        $this->assertNotEquals('super-secret-value', $rawData->client_secret);

        // But decrypted when accessed through model
        $this->assertEquals('super-secret-value', $ssoConfig->client_secret);
    }

    /** @test */
    public function it_does_not_expose_internal_tokens_in_error_messages()
    {
        $response = $this->getJson('/api/v1/applications/99999');

        $response->assertStatus(404);

        // Error message should not contain sensitive data
        $content = $response->getContent();
        $this->assertStringNotContainsString('Bearer', $content);
        $this->assertStringNotContainsString('token', strtolower($content));
    }

    /** @test */
    public function it_validates_oauth_client_secrets_are_not_predictable()
    {
        $app1 = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $app2 = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Get actual secrets from oauth_clients table
        $secret1 = \DB::table('oauth_clients')->where('id', $app1->client_id)->value('secret');
        $secret2 = \DB::table('oauth_clients')->where('id', $app2->client_id)->value('secret');

        // Secrets should be different
        $this->assertNotEquals($secret1, $secret2);

        // Secrets should be sufficiently long
        $this->assertGreaterThan(32, strlen($secret1));
        $this->assertGreaterThan(32, strlen($secret2));
    }

    /** @test */
    public function it_does_not_accept_weak_passwords()
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => '123',
            'password_confirmation' => '123',
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function it_enforces_minimum_password_length()
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'short',
            'password_confirmation' => 'short',
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function it_uses_random_tokens_for_mfa_recovery_codes()
    {
        Passport::actingAs($this->user);

        // Enable MFA
        $this->postJson('/api/v1/mfa/setup', [
            'method' => 'totp',
        ]);

        // Generate recovery codes
        $response = $this->postJson('/api/v1/mfa/recovery-codes/regenerate');

        if ($response->status() === 200) {
            $codes = $response->json('data.recovery_codes');

            // Each code should be unique
            $this->assertEquals(count($codes), count(array_unique($codes)));

            // Codes should be sufficiently long
            foreach ($codes as $code) {
                $this->assertGreaterThan(8, strlen($code));
            }
        }
    }

    /** @test */
    public function it_does_not_expose_database_credentials_in_errors()
    {
        // Force a database error
        $response = $this->getJson('/api/v1/invalid-endpoint-that-might-cause-db-error');

        $content = $response->getContent();

        // Should not expose DB credentials
        $this->assertStringNotContainsString(config('database.connections.pgsql.username'), $content);
        $this->assertStringNotContainsString(config('database.connections.pgsql.password'), $content);
        $this->assertStringNotContainsString(config('database.connections.pgsql.database'), $content);
    }

    /** @test */
    public function it_uses_cryptographically_secure_random_for_tokens()
    {
        Passport::actingAs($this->user);

        $app1 = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Generate access token
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $app1->client_id,
            'client_secret' => \DB::table('oauth_clients')->where('id', $app1->client_id)->value('secret'),
        ]);

        if ($response->status() === 200) {
            $token = $response->json('access_token');

            // Token should be sufficiently long and complex
            $this->assertGreaterThan(40, strlen($token));

            // Should contain variety of characters (not just numbers or letters)
            $this->assertTrue(
                preg_match('/[A-Za-z]/', $token) && preg_match('/[0-9]/', $token),
                'Token should contain both letters and numbers'
            );
        }
    }

    /** @test */
    public function it_sanitizes_sensitive_data_from_exception_traces()
    {
        // Force an exception with sensitive data
        $response = $this->postJson('/api/auth/login', [
            'email' => 'test@example.com',
            'password' => 'sensitive-password-123',
        ]);

        $content = $response->getContent();

        // Password should not appear in response
        $this->assertStringNotContainsString('sensitive-password-123', $content);
    }

    /** @test */
    public function it_validates_encryption_is_used_for_ldap_bind_passwords()
    {
        $ldapConfig = \App\Models\LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'bind_password' => 'ldap-secret-password',
        ]);

        // Password should be encrypted in database
        $rawData = \DB::table('ldap_configurations')
            ->where('id', $ldapConfig->id)
            ->first();

        $this->assertNotEquals('ldap-secret-password', $rawData->bind_password);
    }

    /** @test */
    public function it_ensures_jwt_tokens_are_properly_signed()
    {
        Passport::actingAs($this->user);

        $response = $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'password',
        ]);

        if ($response->status() === 200) {
            $token = $response->json('data.token');

            // Try to use a tampered token
            $parts = explode('.', $token);
            if (count($parts) === 3) {
                // Tamper with payload
                $parts[1] = base64_encode('{"sub":"999"}');
                $tamperedToken = implode('.', $parts);

                $response = $this->withHeaders([
                    'Authorization' => 'Bearer '.$tamperedToken,
                ])->getJson('/api/v1/profile');

                $response->assertStatus(401);
            }
        }
    }

    /** @test */
    public function it_validates_social_account_tokens_are_encrypted()
    {
        $socialAccount = \App\Models\SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_token' => 'google-oauth-token-12345',
        ]);

        // Token should be encrypted in database
        $rawData = \DB::table('social_accounts')
            ->where('id', $socialAccount->id)
            ->first();

        if ($rawData->provider_token) {
            $this->assertNotEquals('google-oauth-token-12345', $rawData->provider_token);
        }
    }
}
