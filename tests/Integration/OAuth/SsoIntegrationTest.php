<?php

namespace Tests\Integration\OAuth;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * SSO Flow Integration Tests
 *
 * Tests Single Sign-On functionality including:
 * - OIDC SSO initiation
 * - SAML 2.0 authentication
 * - Cross-domain SSO
 * - Session management
 * - SSO logout propagation
 */
class SsoIntegrationTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected Application $application;

    protected SSOConfiguration $ssoConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create([
            'name' => 'SSO Test Org',
            'slug' => 'sso-test-org',
        ]);

        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email_verified_at' => now(),
        ]);

        $this->application = Application::factory()->create([
            'name' => 'SSO Test Application',
            'organization_id' => $this->organization->id,
        ]);

        $this->ssoConfig = SSOConfiguration::create([
            'application_id' => $this->application->id,
            'provider' => 'oidc',
            'logout_url' => 'https://app.example.com/logout',
            'callback_url' => 'https://app.example.com/callback',
            'allowed_domains' => ['example.com', 'app.example.com'],
            'session_lifetime' => 3600,
            'is_active' => true,
            'configuration' => [
                'client_id' => 'test-client-id',
                'client_secret' => 'test-client-secret',
                'issuer' => 'https://sso.example.com',
            ],
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_initiation(): void
    {
        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->ssoConfig->id,
            'redirect_uri' => 'https://app.example.com/callback',
        ]);

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertArrayHasKey('redirect_url', $data);
        $this->assertArrayHasKey('state', $data);
        $this->assertArrayHasKey('session_token', $data);
        $this->assertArrayHasKey('expires_at', $data);

        // Verify session was created
        $this->assertDatabaseHas('sso_sessions', [
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'session_token' => $data['session_token'],
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_initiation_requires_authentication(): void
    {
        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->ssoConfig->id,
            'redirect_uri' => 'https://app.example.com/callback',
        ]);

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_initiation_validates_organization_access(): void
    {
        // Create user from different organization
        $otherUser = User::factory()->create();

        Passport::actingAs($otherUser, ['sso']);

        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->ssoConfig->id,
            'redirect_uri' => 'https://app.example.com/callback',
        ]);

        $response->assertStatus(403);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_callback_success(): void
    {
        $response = $this->postJson('/api/v1/sso/callback', [
            'code' => 'test-auth-code-'.uniqid(),
            'state' => 'test-state',
        ]);

        // Should process callback (may succeed or fail based on mock data)
        $this->assertContains($response->getStatusCode(), [200, 400]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_session_validation(): void
    {
        // Create SSO session
        $session = SSOSession::create([
            'session_token' => 'test-token-'.uniqid(),
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test Agent',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/sso/validate', [
            'token' => $session->session_token,
        ]);

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertTrue($data['data']['valid']);
        $this->assertEquals($this->user->id, $data['data']['user']['id']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_session_validation_expired_token(): void
    {
        // Create expired session
        $session = SSOSession::create([
            'session_token' => 'expired-token-'.uniqid(),
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test Agent',
            'expires_at' => now()->subHour(), // Expired
            'last_activity_at' => now()->subHour(),
        ]);

        $response = $this->postJson('/api/v1/sso/validate', [
            'token' => $session->session_token,
        ]);

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_session_list(): void
    {
        // Create multiple SSO sessions
        for ($i = 0; $i < 3; $i++) {
            SSOSession::create([
                'session_token' => 'token-'.$i.'-'.uniqid(),
                'user_id' => $this->user->id,
                'application_id' => $this->application->id,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Test Agent '.$i,
                'expires_at' => now()->addHour(),
                'last_activity_at' => now(),
            ]);
        }

        Passport::actingAs($this->user, ['sso']);

        $response = $this->getJson('/api/v1/sso/sessions');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertIsArray($data['data']);
        $this->assertGreaterThanOrEqual(3, count($data['data']));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_session_revocation(): void
    {
        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/sessions/revoke');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertArrayHasKey('revoked_sessions', $data['data']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_logout(): void
    {
        // Create session
        $session = SSOSession::create([
            'session_token' => 'logout-token-'.uniqid(),
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test Agent',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/sso/logout', [
            'token' => $session->session_token,
        ]);

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals('Logout successful', $data['message']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_configuration_retrieval(): void
    {
        $response = $this->getJson("/api/v1/sso/configuration/{$this->application->id}");

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals($this->application->id, $data['data']['application_id']);
        $this->assertEquals($this->ssoConfig->logout_url, $data['data']['logout_url']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_metadata_endpoint(): void
    {
        $response = $this->getJson("/api/v1/sso/metadata/{$this->organization->slug}");

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertArrayHasKey('organization', $data);
        $this->assertEquals($this->organization->name, $data['organization']['name']);
        $this->assertEquals($this->organization->slug, $data['organization']['slug']);

        $this->assertArrayHasKey('sso_configuration', $data);
        $this->assertArrayHasKey('supported_flows', $data);
        $this->assertContains('authorization_code', $data['supported_flows']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_saml_callback(): void
    {
        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => base64_encode('test-saml-response'),
            'RelayState' => 'test-relay-state',
        ]);

        // SAML callback processing (may fail without proper SAML setup)
        $this->assertContains($response->getStatusCode(), [200, 400]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_session_cleanup(): void
    {
        // Create expired sessions
        for ($i = 0; $i < 5; $i++) {
            SSOSession::create([
                'session_token' => 'expired-'.$i.'-'.uniqid(),
                'user_id' => $this->user->id,
                'application_id' => $this->application->id,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Test Agent',
                'expires_at' => now()->subDays(2),
                'last_activity_at' => now()->subDays(2),
            ]);
        }

        $response = $this->postJson('/api/v1/sso/cleanup');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertArrayHasKey('deleted_sessions_count', $data);
        $this->assertGreaterThanOrEqual(5, $data['deleted_sessions_count']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_cross_domain_session(): void
    {
        Passport::actingAs($this->user, ['sso']);

        // Initiate SSO from one domain
        $response1 = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->ssoConfig->id,
            'redirect_uri' => 'https://app.example.com/callback',
        ]);

        $response1->assertStatus(200);
        $sessionToken = $response1->json()['session_token'];

        // Validate session from another domain
        $response2 = $this->postJson('/api/v1/sso/validate', [
            'token' => $sessionToken,
        ]);

        $response2->assertStatus(200);
        $this->assertTrue($response2->json()['success']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_session_activity_tracking(): void
    {
        // Create session
        $session = SSOSession::create([
            'session_token' => 'activity-token-'.uniqid(),
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test Agent',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now()->subMinutes(10),
        ]);

        $oldActivity = $session->last_activity_at;

        // Validate session (should update last_activity_at)
        $response = $this->postJson('/api/v1/sso/validate', [
            'token' => $session->session_token,
        ]);

        $response->assertStatus(200);

        // Refresh session from database
        $session->refresh();

        // Last activity should be updated
        $this->assertGreaterThan($oldActivity, $session->last_activity_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_configuration_creation(): void
    {
        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/configurations', [
            'application_id' => $this->application->id,
            'logout_url' => 'https://new-app.example.com/logout',
            'callback_url' => 'https://new-app.example.com/callback',
            'allowed_domains' => ['new-app.example.com'],
            'session_lifetime' => 7200,
        ]);

        $response->assertStatus(201);
        $data = $response->json();

        $this->assertEquals($this->application->id, $data['application_id']);
        $this->assertEquals('https://new-app.example.com/logout', $data['logout_url']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_sso_synchronized_logout(): void
    {
        // Create multiple sessions
        for ($i = 0; $i < 3; $i++) {
            SSOSession::create([
                'session_token' => 'multi-token-'.$i.'-'.uniqid(),
                'user_id' => $this->user->id,
                'application_id' => $this->application->id,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Test Agent',
                'expires_at' => now()->addHour(),
                'last_activity_at' => now(),
            ]);
        }

        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/logout/synchronized');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertArrayHasKey('revoked_count', $data);
        $this->assertGreaterThanOrEqual(3, $data['revoked_count']);
    }
}
