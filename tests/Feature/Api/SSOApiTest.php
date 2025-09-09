<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class SSOApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private User $user;

    private Application $application;

    private SSOConfiguration $ssoConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->withSso()->create();
        $this->user = User::factory()->forOrganization($this->organization)->create();
        $this->application = Application::factory()->forOrganization($this->organization)->create();

        $this->ssoConfig = SSOConfiguration::factory()
            ->forApplication($this->application)
            ->oidc()
            ->create();

        // Grant user access to the application
        $this->user->applications()->attach($this->application->id, [
            'granted_at' => now(),
            'granted_by' => $this->user->id,
        ]);

        Role::create(['name' => 'user', 'guard_name' => 'web']);
    }

    public function test_initiate_sso_flow_returns_redirect_url(): void
    {
        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->ssoConfig->id,
            'redirect_uri' => 'http://localhost:3000/callback',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'redirect_url',
                'state',
                'session_token',
                'expires_at',
            ]);

        $this->assertStringContainsString(
            $this->ssoConfig->configuration['authorization_endpoint'],
            $response->json('redirect_url')
        );

        // Verify session was created
        $this->assertDatabaseHas('sso_sessions', [
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'session_token' => $response->json('session_token'),
        ]);
    }

    public function test_initiate_sso_flow_validates_application_access(): void
    {
        $otherApplication = Application::factory()->create();

        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $otherApplication->id,
            'sso_configuration_id' => $this->ssoConfig->id,
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Access denied to this application',
            ]);
    }

    public function test_handle_sso_callback_processes_successful_response(): void
    {
        // Create pending SSO session
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create([
                'external_session_id' => 'test-state-123',
                'metadata' => ['sso_configuration_id' => $this->ssoConfig->id],
            ]);

        // Mock OIDC token exchange
        Http::fake([
            $this->ssoConfig->configuration['token_endpoint'] => Http::response([
                'access_token' => 'access-token-123',
                'id_token' => 'id-token-123',
                'refresh_token' => 'refresh-token-123',
                'expires_in' => 3600,
            ], 200),
            $this->ssoConfig->configuration['userinfo_endpoint'] => Http::response([
                'sub' => 'user-123',
                'email' => $this->user->email,
                'name' => $this->user->name,
                'email_verified' => true,
            ], 200),
        ]);

        $response = $this->postJson('/api/v1/sso/callback', [
            'code' => 'auth-code-123',
            'state' => 'test-state-123',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'user' => [
                    'id',
                    'name',
                    'email',
                ],
                'session' => [
                    'session_token',
                    'expires_at',
                ],
                'application' => [
                    'id',
                    'name',
                    'redirect_uri',
                ],
            ])
            ->assertJson([
                'success' => true,
            ]);

        // Verify session was updated with token information
        // Fetch fresh session instance from database
        $updatedSession = SSOSession::find($session->id);

        $this->assertArrayHasKey('access_token', $updatedSession->metadata);
        $this->assertArrayHasKey('user_info', $updatedSession->metadata);
    }

    public function test_handle_sso_callback_fails_with_invalid_state(): void
    {
        $response = $this->postJson('/api/v1/sso/callback', [
            'code' => 'auth-code-123',
            'state' => 'invalid-state',
        ]);

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'error' => 'Invalid or expired SSO session',
            ]);
    }

    public function test_handle_sso_callback_handles_token_exchange_failure(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create([
                'external_session_id' => 'test-state-123',
                'metadata' => ['sso_configuration_id' => $this->ssoConfig->id],
            ]);

        // Mock failed token exchange
        Http::fake([
            $this->ssoConfig->configuration['token_endpoint'] => Http::response([
                'error' => 'invalid_grant',
                'error_description' => 'The provided authorization grant is invalid',
            ], 400),
        ]);

        $response = $this->postJson('/api/v1/sso/callback', [
            'code' => 'invalid-code',
            'state' => 'test-state-123',
        ]);

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'error' => 'Token exchange failed',
            ]);
    }

    public function test_validate_sso_session_returns_session_info(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->recentlyActive()
            ->create();

        Passport::actingAs($this->user, ['sso']);

        $response = $this->getJson("/api/v1/sso/sessions/{$session->session_token}/validate");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'valid',
                'session' => [
                    'id',
                    'session_token',
                    'user_id',
                    'application_id',
                    'expires_at',
                    'last_activity_at',
                ],
                'user' => [
                    'id',
                    'name',
                    'email',
                ],
            ])
            ->assertJson([
                'valid' => true,
            ]);
    }

    public function test_validate_sso_session_fails_for_expired_session(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->expired()
            ->create();

        Passport::actingAs($this->user, ['sso']);

        $response = $this->getJson("/api/v1/sso/sessions/{$session->session_token}/validate");

        $response->assertStatus(400)
            ->assertJson([
                'valid' => false,
                'error' => 'Session has expired',
            ]);
    }

    public function test_refresh_sso_token_updates_session_tokens(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create([
                'refresh_token' => 'refresh-token-123',
                'metadata' => [
                    'sso_configuration_id' => $this->ssoConfig->id,
                    'access_token' => 'old-access-token',
                ],
            ]);

        // Mock successful token refresh
        Http::fake([
            $this->ssoConfig->configuration['token_endpoint'] => Http::response([
                'access_token' => 'new-access-token-123',
                'refresh_token' => 'new-refresh-token-123',
                'expires_in' => 3600,
            ], 200),
        ]);

        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson("/api/v1/sso/sessions/{$session->session_token}/refresh");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'access_token',
                'expires_at',
            ])
            ->assertJson([
                'success' => true,
                'access_token' => 'new-access-token-123',
            ]);

        // Verify session was updated
        $updatedSession = SSOSession::find($session->id);
        $this->assertEquals('new-access-token-123', $updatedSession->metadata['access_token']);
        $this->assertEquals('new-refresh-token-123', $updatedSession->refresh_token);
    }

    public function test_logout_sso_session_invalidates_session(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->recentlyActive()
            ->create();

        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson("/api/v1/sso/sessions/{$session->session_token}/logout");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'SSO session logged out successfully',
            ]);

        // Verify session is logged out
        $updatedSession = SSOSession::find($session->id);
        $this->assertNotNull($updatedSession->logged_out_at);
        $this->assertEquals($this->user->id, $updatedSession->logged_out_by);
    }

    public function test_synchronized_logout_revokes_all_user_sessions(): void
    {
        // Create multiple active sessions for the user
        $sessions = SSOSession::factory()
            ->count(3)
            ->forUser($this->user)
            ->recentlyActive()
            ->create();

        // Create session for other user (should not be affected)
        $otherUser = User::factory()->forOrganization($this->organization)->create();
        $otherSession = SSOSession::factory()
            ->forUser($otherUser)
            ->recentlyActive()
            ->create();

        Passport::actingAs($this->user, ['sso']);

        $response = $this->postJson('/api/v1/sso/logout/synchronized');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'All SSO sessions logged out successfully',
                'revoked_count' => 3,
            ]);

        // Verify all user's sessions are logged out
        foreach ($sessions as $session) {
            $updatedSession = SSOSession::find($session->id);
            $this->assertNotNull($updatedSession->logged_out_at);
        }

        // Verify other user's session is not affected
        $updatedOtherSession = SSOSession::find($otherSession->id);
        $this->assertNull($updatedOtherSession->logged_out_at);
    }

    public function test_get_active_sso_sessions_returns_user_sessions(): void
    {
        // Create active sessions
        $activeSessions = SSOSession::factory()
            ->count(2)
            ->forUser($this->user)
            ->recentlyActive()
            ->create();

        // Create expired session (should not appear)
        SSOSession::factory()
            ->forUser($this->user)
            ->expired()
            ->create();

        // Create other user's session (should not appear)
        $otherUser = User::factory()->forOrganization($this->organization)->create();
        SSOSession::factory()
            ->forUser($otherUser)
            ->recentlyActive()
            ->create();

        Passport::actingAs($this->user, ['sso']);

        $response = $this->getJson('/api/v1/sso/sessions');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'session_token',
                        'application' => [
                            'id',
                            'name',
                        ],
                        'ip_address',
                        'user_agent',
                        'last_activity_at',
                        'expires_at',
                    ],
                ],
            ])
            ->assertJsonCount(2, 'data');
    }

    public function test_get_sso_configuration_returns_organization_config(): void
    {
        Passport::actingAs($this->user, ['sso']);

        $response = $this->getJson("/api/v1/sso/configurations/{$this->organization->id}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'id',
                'name',
                'provider',
                'is_active',
                'configuration' => [
                    'authorization_endpoint',
                    'token_endpoint',
                    'userinfo_endpoint',
                ],
            ])
            ->assertJson([
                'id' => $this->ssoConfig->id,
                'provider' => 'oidc',
                'is_active' => true,
            ]);
    }

    public function test_get_sso_configuration_returns_null_for_inactive_config(): void
    {
        $this->ssoConfig->update(['is_active' => false]);

        Passport::actingAs($this->user, ['sso']);

        $response = $this->getJson("/api/v1/sso/configurations/{$this->organization->id}");

        $response->assertStatus(404)
            ->assertJson([
                'message' => 'No active SSO configuration found for this organization',
            ]);
    }

    public function test_sso_api_enforces_organization_isolation(): void
    {
        $otherOrg = Organization::factory()->create();
        $otherConfig = SSOConfiguration::factory()
            ->forOrganization($otherOrg)
            ->create();

        Passport::actingAs($this->user, ['sso']);

        // Try to initiate SSO with other organization's config
        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $otherConfig->id,
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'SSO configuration does not belong to the same organization',
            ]);
    }

    public function test_sso_api_requires_proper_scopes(): void
    {
        // Try to access SSO API without proper scopes
        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/sso/initiate', [
            'application_id' => $this->application->id,
            'sso_configuration_id' => $this->ssoConfig->id,
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Insufficient permissions',
            ]);
    }

    public function test_handle_saml_callback_processes_saml_response(): void
    {
        $samlConfig = SSOConfiguration::factory()
            ->forOrganization($this->organization)
            ->saml2()
            ->create();

        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create([
                'external_session_id' => 'saml-request-123',
                'metadata' => ['sso_configuration_id' => $samlConfig->id],
            ]);

        $samlResponse = base64_encode('<saml:Assertion>Mock SAML Response</saml:Assertion>');

        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => $samlResponse,
            'RelayState' => 'saml-request-123',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'user',
                'session',
                'application',
            ])
            ->assertJson([
                'success' => true,
            ]);
    }

    public function test_sso_session_cleanup_removes_expired_sessions(): void
    {
        // Create expired sessions
        SSOSession::factory()
            ->count(5)
            ->expired()
            ->forUser($this->user)
            ->create();

        // Create active session (should remain)
        $activeSession = SSOSession::factory()
            ->forUser($this->user)
            ->recentlyActive()
            ->create();

        $response = $this->postJson('/api/v1/sso/cleanup');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Cleanup completed successfully',
                'deleted_sessions_count' => 5,
            ]);

        // Verify only active session remains
        $this->assertDatabaseHasModel($activeSession);
        $this->assertDatabaseCount('sso_sessions', 1);
    }

    public function test_sso_metadata_endpoint_returns_organization_metadata(): void
    {
        $response = $this->getJson("/api/v1/sso/metadata/{$this->organization->slug}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'organization' => [
                    'name',
                    'slug',
                ],
                'sso_configuration' => [
                    'provider',
                    'endpoints',
                ],
                'supported_flows',
                'security_requirements',
            ]);
    }
}
