<?php

namespace Tests\Unit\Services;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use App\Services\SSOService;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class SSOServiceTest extends TestCase
{
    private SSOService $ssoService;

    private Organization $organization;

    private Application $application;

    private User $user;

    private SSOConfiguration $ssoConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->ssoService = app(SSOService::class);
        $this->organization = Organization::factory()->withSso()->create();
        $this->application = Application::factory()->forOrganization($this->organization)->create();
        $this->user = User::factory()->forOrganization($this->organization)->create();

        $this->ssoConfig = SSOConfiguration::factory()
            ->forApplication($this->application)
            ->oidc()
            ->create();

        // Grant user access to the application
        $this->user->applications()->attach($this->application->id, [
            'permissions' => ['read', 'write'],
            'granted_at' => now(),
        ]);
    }

    public function test_initiate_sso_flow_creates_session_and_returns_redirect_url(): void
    {
        $result = $this->ssoService->initiateSSOFlow(
            $this->user->id,
            $this->application->id,
            $this->ssoConfig->id
        );

        $this->assertArrayHasKey('redirect_url', $result);
        $this->assertArrayHasKey('session_token', $result);
        $this->assertArrayHasKey('state', $result);

        $this->assertStringContainsString($this->ssoConfig->configuration['authorization_endpoint'], $result['redirect_url']);

        $this->assertDatabaseHas('sso_sessions', [
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'session_token' => $result['session_token'],
        ]);
    }

    public function test_initiate_sso_flow_throws_exception_for_inactive_config(): void
    {
        $inactiveConfig = SSOConfiguration::factory()
            ->forOrganization($this->organization)
            ->inactive()
            ->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('SSO configuration is not active');

        $this->ssoService->initiateSSOFlow(
            $this->user->id,
            $this->application->id,
            $inactiveConfig->id
        );
    }

    public function test_initiate_sso_flow_throws_exception_for_mismatched_organization(): void
    {
        $otherOrganization = Organization::factory()->create();
        $otherConfig = SSOConfiguration::factory()->forOrganization($otherOrganization)->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('SSO configuration does not belong to the same organization');

        $this->ssoService->initiateSSOFlow(
            $this->user->id,
            $this->application->id,
            $otherConfig->id
        );
    }

    public function test_validate_sso_session_returns_valid_session(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->recentlyActive()
            ->create();

        $validatedSession = $this->ssoService->validateSSOSession($session->session_token);

        $this->assertInstanceOf(SSOSession::class, $validatedSession);
        $this->assertEquals($session->id, $validatedSession->id);
    }

    public function test_validate_sso_session_throws_exception_for_expired_session(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->expired()
            ->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Session has expired');

        $this->ssoService->validateSSOSession($session->session_token);
    }

    public function test_validate_sso_session_throws_exception_for_invalid_token(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid SSO session token');

        $this->ssoService->validateSSOSession('invalid-token');
    }

    public function test_handle_oidc_callback_processes_successful_response(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->withSSOState()
            ->create();

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

        $result = $this->ssoService->handleOIDCCallback([
            'code' => 'auth-code-123',
            'state' => $session->external_session_id,
        ]);

        $this->assertTrue($result['success']);
        $this->assertArrayHasKey('user', $result);
        $this->assertArrayHasKey('session', $result);

        // Use fresh session instance to get updated metadata
        $updatedSession = SSOSession::find($session->id);

        $this->assertNotNull($updatedSession->metadata['access_token']);
        $this->assertNotNull($updatedSession->metadata['user_info']);
    }

    public function test_handle_oidc_callback_handles_token_exchange_failure(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->withSSOState()
            ->create();

        Http::fake([
            $this->ssoConfig->configuration['token_endpoint'] => Http::response([
                'error' => 'invalid_grant',
                'error_description' => 'The provided authorization grant is invalid',
            ], 400),
        ]);

        $result = $this->ssoService->handleOIDCCallback([
            'code' => 'invalid-code',
            'state' => $session->external_session_id,
        ]);

        $this->assertFalse($result['success']);
        $this->assertEquals('Token exchange failed', $result['error']);
    }

    public function test_synchronized_logout_revokes_all_user_sessions(): void
    {
        // Create multiple SSO sessions for the user
        $sessions = SSOSession::factory()
            ->count(3)
            ->forUser($this->user)
            ->recentlyActive()
            ->create();

        // Create sessions for other users (should not be affected)
        $otherUser = User::factory()->forOrganization($this->organization)->create();
        $otherSession = SSOSession::factory()->forUser($otherUser)->create();

        $result = $this->ssoService->synchronizedLogout($this->user->id);

        $this->assertTrue($result);

        // Verify all user's sessions are marked as expired (use fresh instances)
        $sessionIds = $sessions->pluck('id');
        $freshSessions = SSOSession::whereIn('id', $sessionIds)->get();

        foreach ($freshSessions as $freshSession) {
            $this->assertNotNull($freshSession->logged_out_at);
        }

        // Verify other user's session is not affected (use fresh instance)
        $freshOtherSession = SSOSession::find($otherSession->id);
        $this->assertNull($freshOtherSession->logged_out_at);

        // Verify cache invalidation
        $this->assertFalse(Cache::has("sso_sessions:{$this->user->id}"));
    }

    public function test_revoke_sso_session_invalidates_specific_session(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create();

        $result = $this->ssoService->revokeSSOSession($session->session_token, $this->user->id);

        $this->assertTrue($result);

        // Use fresh instance to check logout status
        $freshSession = SSOSession::find($session->id);
        $this->assertNotNull($freshSession->logged_out_at);
        $this->assertEquals($this->user->id, $freshSession->logged_out_by);
    }

    public function test_revoke_sso_session_throws_exception_for_unauthorized_user(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create();

        $otherUser = User::factory()->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Not authorized to revoke this session');

        $this->ssoService->revokeSSOSession($session->session_token, $otherUser->id);
    }

    public function test_get_active_sso_sessions_returns_user_sessions(): void
    {
        // Create active sessions for the user
        SSOSession::factory()
            ->count(2)
            ->forUser($this->user)
            ->recentlyActive()
            ->create();

        // Create expired session (should not be included)
        SSOSession::factory()
            ->forUser($this->user)
            ->expired()
            ->create();

        // Create session for other user (should not be included)
        $otherUser = User::factory()->create();
        SSOSession::factory()->forUser($otherUser)->create();

        $activeSessions = $this->ssoService->getActiveSSOSessions($this->user->id);

        $this->assertCount(2, $activeSessions);
        foreach ($activeSessions as $session) {
            $this->assertEquals($this->user->id, $session->user_id);
            $this->assertNull($session->logged_out_at);
            $this->assertTrue($session->expires_at->isFuture());
        }
    }

    public function test_validate_saml_response_processes_saml_assertion(): void
    {
        $samlConfig = SSOConfiguration::factory()
            ->forOrganization($this->organization)
            ->saml2()
            ->create();

        // Mock SAML response
        $samlResponse = base64_encode('<saml:Assertion>Mock SAML Response</saml:Assertion>');

        // Create pending session
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create(['metadata' => ['saml_request_id' => 'request-123']]);

        $result = $this->ssoService->validateSAMLResponse($samlResponse, 'request-123');

        $this->assertTrue($result['success']);
        $this->assertArrayHasKey('user_info', $result);
    }

    public function test_refresh_sso_token_updates_session_with_new_tokens(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->forApplication($this->application)
            ->create([
                'refresh_token' => 'refresh-token-123',
                'metadata' => ['access_token' => 'old-token'],
            ]);

        Http::fake([
            $this->ssoConfig->configuration['token_endpoint'] => Http::response([
                'access_token' => 'new-access-token-123',
                'refresh_token' => 'new-refresh-token-123',
                'expires_in' => 3600,
            ], 200),
        ]);

        $result = $this->ssoService->refreshSSOToken($session->session_token);

        $this->assertTrue($result['success']);
        $this->assertEquals('new-access-token-123', $result['access_token']);

        // Use fresh instance to check updated tokens
        $freshSession = SSOSession::find($session->id);
        $this->assertEquals('new-access-token-123', $freshSession->metadata['access_token']);
        $this->assertEquals('new-refresh-token-123', $freshSession->refresh_token);
    }

    public function test_get_sso_configuration_returns_active_config_for_organization(): void
    {
        $config = $this->ssoService->getSSOConfiguration($this->organization->id);

        $this->assertInstanceOf(SSOConfiguration::class, $config);
        $this->assertEquals($this->ssoConfig->id, $config->id);
        $this->assertTrue($config->is_active);
    }

    public function test_get_sso_configuration_returns_null_for_no_active_config(): void
    {
        $this->ssoConfig->update(['is_active' => false]);

        $config = $this->ssoService->getSSOConfiguration($this->organization->id);

        $this->assertNull($config);
    }

    public function test_cleanup_expired_sessions_removes_old_sessions(): void
    {
        // Create expired sessions
        SSOSession::factory()
            ->count(3)
            ->expired()
            ->forUser($this->user)
            ->create();

        // Create active session (should not be deleted)
        $activeSession = SSOSession::factory()
            ->forUser($this->user)
            ->recentlyActive()
            ->create();

        $deletedCount = $this->ssoService->cleanupExpiredSessions();

        $this->assertEquals(3, $deletedCount);
        $this->assertDatabaseHasModel($activeSession);
        $this->assertDatabaseCount('sso_sessions', 1);
    }
}
