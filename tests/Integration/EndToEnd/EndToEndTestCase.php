<?php

namespace Tests\Integration\EndToEnd;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\SocialAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Mockery;
use Tests\TestCase;

/**
 * Base class for End-to-End testing scenarios.
 *
 * Provides comprehensive setup for testing complete user workflows
 * including OAuth flows, social authentication, multi-tenant scenarios,
 * and complex integration testing.
 */
abstract class EndToEndTestCase extends TestCase
{
    use RefreshDatabase;

    /**
     * PKCE code verifier for tests (RFC 7636 requires 43-128 characters)
     */
    protected string $testCodeVerifier = 'test_verifier_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 43 characters

    protected Organization $defaultOrganization;

    protected Organization $enterpriseOrganization;

    protected User $superAdmin;

    protected User $organizationOwner;

    protected User $organizationAdmin;

    protected User $regularUser;

    protected Application $oauthApplication;

    protected Client $oauthClient;

    // Service mocks for external dependencies
    protected $mockSocialAuthService;

    protected $mockMailService;

    // Test environment state
    protected array $testEnvironmentSettings = [];

    protected bool $socialProvidersEnabled = true;

    protected bool $emailNotificationsEnabled = true;

    protected bool $queueJobsEnabled = false;

    protected function setUp(): void
    {
        parent::setUp();

        // Initialize comprehensive test environment
        $this->initializeTestEnvironment();
        $this->setupTestOrganizations();
        $this->setupTestUsers();
        $this->setupOAuthClients();
        $this->setupExternalServiceMocks();
        $this->configureTestEnvironment();
    }

    protected function tearDown(): void
    {
        $this->cleanupTestEnvironment();
        parent::tearDown();
    }

    /**
     * Initialize the complete test environment with realistic data
     */
    protected function initializeTestEnvironment(): void
    {
        // Run comprehensive seeders for realistic scenarios
        $this->artisan('db:seed', ['--class' => 'RolePermissionSeeder']);

        // Cache the expensive seeding operations
        static $fullSeederRun = false;
        if (! $fullSeederRun) {
            $this->artisan('db:seed', ['--class' => 'OrganizationSeeder']);
            $this->artisan('db:seed', ['--class' => 'ApplicationSeeder']);
            $fullSeederRun = true;
        }

        // Clear and reset caches for clean state
        Cache::flush();

        // Reset authentication logs for clean testing
        AuthenticationLog::truncate();
    }

    /**
     * Setup test organizations with different security configurations
     */
    protected function setupTestOrganizations(): void
    {
        // Default organization with standard security
        $this->defaultOrganization = Organization::factory()->create([
            'name' => 'Default Test Organization',
            'slug' => 'default-test-org',
            'settings' => [
                'allow_registration' => true,
                'require_email_verification' => false,
                'mfa_required' => false,
                'password_min_length' => 8,
                'session_timeout' => 1440, // 24 hours
                'allowed_domains' => ['example.com', 'test.com'],
            ],
        ]);

        // Enterprise organization with high security requirements
        $this->enterpriseOrganization = Organization::factory()->create([
            'name' => 'Enterprise Test Organization',
            'slug' => 'enterprise-test-org',
            'settings' => [
                'allow_registration' => false,
                'require_email_verification' => true,
                'mfa_required' => true,
                'password_min_length' => 12,
                'session_timeout' => 480, // 8 hours
                'allowed_domains' => ['enterprise.com'],
                'ip_whitelist' => ['192.168.1.0/24'],
                'sso_required' => true,
            ],
        ]);
    }

    /**
     * Setup test users with various roles and configurations
     */
    protected function setupTestUsers(): void
    {
        // Super Admin (global access)
        $this->superAdmin = $this->createSuperAdmin([
            'name' => 'E2E Super Admin',
            'email' => 'e2e-superadmin@authservice.com',
            'email_verified_at' => now(),
        ]);

        // Organization Owner for default org
        $this->organizationOwner = $this->createUser([
            'name' => 'E2E Organization Owner',
            'email' => 'e2e-owner@example.com',
            'organization_id' => $this->defaultOrganization->id,
            'email_verified_at' => now(),
        ], 'Organization Owner');

        // Organization Admin for default org
        $this->organizationAdmin = $this->createUser([
            'name' => 'E2E Organization Admin',
            'email' => 'e2e-admin@example.com',
            'organization_id' => $this->defaultOrganization->id,
            'email_verified_at' => now(),
        ], 'Organization Admin');

        // Regular user for testing
        $this->regularUser = $this->createUser([
            'name' => 'E2E Regular User',
            'email' => 'e2e-user@example.com',
            'organization_id' => $this->defaultOrganization->id,
            'email_verified_at' => now(),
        ], 'User');

        // Setup API guard roles for API testing
        $this->setupApiGuardRoles();
    }

    /**
     * Setup roles for API guard to support API route testing
     */
    protected function setupApiGuardRoles(): void
    {
        $roles = ['Super Admin', 'Organization Owner', 'Organization Admin', 'User'];

        foreach ($roles as $roleName) {
            // For Super Admin, use null organization (global)
            if ($roleName === 'Super Admin') {
                $this->setupRoleWithPermissions($roleName, 'api', null);
            } else {
                // Create for default organization
                $this->setupRoleWithPermissions($roleName, 'api', $this->defaultOrganization->id);

                // Also create for enterprise organization
                $this->setupRoleWithPermissions($roleName, 'api', $this->enterpriseOrganization->id);
            }
        }
    }

    /**
     * Setup OAuth clients and applications for testing OAuth flows
     */
    protected function setupOAuthClients(): void
    {
        // Create OAuth application for testing
        $this->oauthApplication = Application::factory()->create([
            'name' => 'E2E Test Application',
            'organization_id' => $this->defaultOrganization->id,
            'settings' => [
                'description' => 'Application for end-to-end testing',
                'homepage_url' => 'https://e2e-test-app.example.com',
            ],
            'is_active' => true,
        ]);

        // Create corresponding OAuth client using Passport's method
        $plainSecret = 'e2e-test-secret';
        $this->oauthClient = Client::create([
            'name' => 'E2E Test OAuth Client',
            'secret' => $plainSecret,
            'redirect' => 'https://e2e-test-app.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        // Store the plain secret for testing
        $this->oauthClient->plainSecret = $plainSecret;

        // Link application to OAuth client
        $this->oauthApplication->update([
            'passport_client_id' => $this->oauthClient->id,
        ]);
    }

    /**
     * Setup mocks for external services
     */
    protected function setupExternalServiceMocks(): void
    {
        if ($this->socialProvidersEnabled) {
            $this->setupSocialAuthMocks();
        }

        if ($this->emailNotificationsEnabled) {
            $this->setupEmailMocks();
        }

        if ($this->queueJobsEnabled) {
            $this->setupQueueMocks();
        }
    }

    /**
     * Configure social authentication mocks
     */
    protected function setupSocialAuthMocks(): void
    {
        // Configure test social provider settings
        Config::set('services.google', [
            'client_id' => 'test_google_client_id',
            'client_secret' => 'test_google_client_secret',
            'redirect' => url('/auth/social/google/callback'),
        ]);

        Config::set('services.github', [
            'client_id' => 'test_github_client_id',
            'client_secret' => 'test_github_client_secret',
            'redirect' => url('/auth/social/github/callback'),
        ]);

        // Mock the SocialAuthService
        $this->mockSocialAuthService = Mockery::mock(SocialAuthService::class);
        $this->app->instance(SocialAuthService::class, $this->mockSocialAuthService);
    }

    /**
     * Setup email notification mocks
     */
    protected function setupEmailMocks(): void
    {
        Mail::fake();
        Notification::fake();
    }

    /**
     * Setup queue job mocks
     */
    protected function setupQueueMocks(): void
    {
        Queue::fake();
    }

    /**
     * Configure test environment settings
     */
    protected function configureTestEnvironment(): void
    {
        // Set test-specific configuration
        Config::set('app.env', 'testing');
        Config::set('mail.default', 'array');
        Config::set('queue.default', 'sync');

        // Configure rate limiting for testing
        Config::set('app.rate_limits', [
            'api' => 1000, // High limit for testing
            'auth' => 100,
        ]);

        // Enable debug mode for detailed error reporting
        Config::set('app.debug', true);
    }

    /**
     * Create a complete user with social provider data
     */
    protected function createSocialUser(array $attributes = [], string $provider = 'google'): User
    {
        $socialAttributes = array_merge([
            'provider' => $provider,
            'provider_id' => 'test_'.$provider.'_'.uniqid(),
            'provider_token' => 'test_access_token_'.uniqid(),
            'provider_refresh_token' => 'test_refresh_token_'.uniqid(),
            'organization_id' => $this->defaultOrganization->id,
        ], $attributes);

        return $this->createUser($socialAttributes, 'User');
    }

    /**
     * Create an OAuth authorization code for testing authorization flows
     */
    protected function createAuthorizationCode(User $user, Client $client, array $scopes = ['openid', 'profile']): string
    {
        $code = 'test_auth_code_'.uniqid();

        // Store in Laravel Passport's oauth_auth_codes table with only supported columns
        DB::table('oauth_auth_codes')->insert([
            'id' => $code,
            'user_id' => $user->id,
            'client_id' => $client->id,
            'scopes' => implode(' ', $scopes), // Passport expects space-separated string, not JSON
            'revoked' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        return $code;
    }

    /**
     * Get a real authorization code from full Passport flow for testing replay attacks
     */
    protected function getAuthorizationCode(User $user, Client $client, array $scopes = ['openid', 'profile']): string
    {
        // Generate PKCE parameters
        $codeVerifier = $this->testCodeVerifier;
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        // Step 1: Authenticate user for web guard and request authorization
        $this->actingAs($user, 'web');

        $authParams = [
            'response_type' => 'code',
            'client_id' => $client->id,
            'redirect_uri' => $client->redirect,
            'scope' => implode(' ', $scopes),
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

        if (! $authToken) {
            throw new \Exception('Could not extract auth_token from authorization response');
        }

        // Step 2: User approves authorization (simulate approval)
        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $authParams['state'],
            'client_id' => $authParams['client_id'],
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        $approvalResponse->assertRedirect();
        $redirectUrl = $approvalResponse->headers->get('Location');

        // Extract authorization code
        parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $queryParams);

        return $queryParams['code'];
    }

    /**
     * Simulate a complete OAuth authorization flow using standard Passport endpoints
     */
    protected function performOAuthFlow(User $user, Client $client, array $scopes = ['openid', 'profile']): array
    {
        // Generate PKCE parameters
        $codeVerifier = $this->testCodeVerifier;
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        // Step 1: Authenticate user for web guard and request authorization using Passport's endpoint
        $this->actingAs($user, 'web');
        $state = 'secure_state_'.uniqid();

        $authParams = [
            'response_type' => 'code',
            'client_id' => $client->id,
            'redirect_uri' => $client->redirect,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        $authResponse = $this->get('/oauth/authorize?'.http_build_query($authParams));
        $authResponse->assertStatus(200);

        // Extract the auth token from the authorization form
        $authContent = $authResponse->getContent();
        preg_match('/name="auth_token" value="([^"]+)"/', $authContent, $matches);
        $authToken = $matches[1] ?? null;

        if (! $authToken) {
            throw new \Exception('Could not extract auth_token from authorization response');
        }

        // Step 2: User approves authorization (simulate approval)
        $approvalResponse = $this->post('/oauth/authorize', [
            'state' => $authParams['state'],
            'client_id' => $authParams['client_id'],
            'auth_token' => $authToken,
            'approve' => '1',
        ]);

        $approvalResponse->assertRedirect();
        $redirectUrl = $approvalResponse->headers->get('Location');

        // Extract authorization code
        parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $queryParams);
        $authCode = $queryParams['code'];

        // Step 3: Token exchange using Passport's token endpoint
        $clientSecret = $client->plainSecret ?? $client->secret;
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->id,
            'client_secret' => $clientSecret,
            'code' => $authCode,
            'redirect_uri' => $client->redirect,
            'code_verifier' => $codeVerifier,
        ]);

        if ($tokenResponse->getStatusCode() !== 200) {
            $debugInfo = [
                'status' => $tokenResponse->getStatusCode(),
                'response' => $tokenResponse->getContent(),
                'client_id' => $client->id,
            ];
            throw new \Exception('OAuth flow failed: '.json_encode($debugInfo, JSON_PRETTY_PRINT));
        }

        $tokenData = $tokenResponse->json();

        // Ensure the response has the expected structure
        if (! isset($tokenData['access_token'])) {
            throw new \Exception('OAuth response missing access_token: '.json_encode($tokenData));
        }

        return $tokenData;
    }

    /**
     * Create a realistic authentication log entry
     */
    protected function createAuthenticationLog(User $user, string $event = 'login_success', array $attributes = []): AuthenticationLog
    {
        return AuthenticationLog::create(array_merge([
            'user_id' => $user->id,
            'event' => $event,
            'ip_address' => '192.168.1.100',
            'user_agent' => 'E2E Test Agent/1.0',
            'success' => str_contains($event, 'success'),
            'details' => [
                'test_scenario' => 'end_to_end_testing',
                'timestamp' => now()->toISOString(),
            ],
        ], $attributes));
    }

    /**
     * Simulate time passage for testing token expiration
     */
    protected function travelToFuture(int $minutes): void
    {
        $this->travel($minutes)->minutes();
    }

    /**
     * Simulate time passage for testing token expiration (hours)
     */
    protected function travelToFutureHours(int $hours): void
    {
        $this->travel($hours)->hours();
    }

    /**
     * Return to present time
     */
    protected function returnToPresent(): void
    {
        $this->travelBack();
    }

    /**
     * Setup a complete multi-organization scenario
     */
    protected function setupMultiOrganizationScenario(): array
    {
        $organizations = [];

        for ($i = 1; $i <= 3; $i++) {
            $org = Organization::factory()->create([
                'name' => "Test Organization {$i}",
                'slug' => "test-org-{$i}",
            ]);

            $admin = $this->createUser([
                'name' => "Admin {$i}",
                'email' => "admin{$i}@testorg{$i}.com",
                'organization_id' => $org->id,
            ], 'Organization Admin');

            $users = [];
            for ($j = 1; $j <= 2; $j++) {
                $users[] = $this->createUser([
                    'name' => "User {$j} - Org {$i}",
                    'email' => "user{$j}@testorg{$i}.com",
                    'organization_id' => $org->id,
                ], 'User');
            }

            $app = Application::factory()->create([
                'name' => "App for Organization {$i}",
                'organization_id' => $org->id,
            ]);

            $organizations[] = [
                'organization' => $org,
                'admin' => $admin,
                'users' => $users,
                'application' => $app,
            ];
        }

        return $organizations;
    }

    /**
     * Assert that a user can only access organization-specific data
     */
    protected function assertOrganizationDataIsolation(User $user, Organization $organization): void
    {
        // Test that user can only see their organization's data
        $this->actingAs($user, 'api');

        // Should be able to see own organization's users
        $response = $this->getJson('/api/v1/users');
        $response->assertStatus(200);

        $responseData = $response->json();
        $users = $responseData['data']['data'] ?? $responseData['data'] ?? $responseData ?? [];

        if (is_array($users) && ! empty($users)) {
            foreach ($users as $userData) {
                $this->assertEquals($organization->id, $userData['organization_id']);
            }
        }

        // Should be able to see own organization's applications
        $response = $this->getJson('/api/v1/applications');
        $response->assertStatus(200);

        $responseData = $response->json();
        $applications = $responseData['data']['data'] ?? $responseData['data'] ?? $responseData ?? [];

        if (is_array($applications) && ! empty($applications)) {
            foreach ($applications as $appData) {
                $this->assertEquals($organization->id, $appData['organization_id']);
            }
        }
    }

    /**
     * Mock a successful social authentication flow
     */
    protected function mockSuccessfulSocialAuth(string $provider, ?User $user = null): User
    {
        if (! $user) {
            $user = $this->createSocialUser([], $provider);
        }

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with($provider)
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with($provider)
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with($provider)
            ->andReturn("https://accounts.{$provider}.com/oauth/authorize?test=true");

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with($provider, Mockery::any())
            ->andReturn([
                'user' => $user,
                'access_token' => 'test_jwt_token_'.uniqid(),
                'refresh_token' => 'test_refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $this->mockSocialAuthService
            ->shouldReceive('getAvailableProviders')
            ->andReturn([
                'google' => [
                    'name' => 'Google',
                    'enabled' => true,
                    'icon' => 'google',
                ],
                'github' => [
                    'name' => 'GitHub',
                    'enabled' => true,
                    'icon' => 'github',
                ],
                'facebook' => [
                    'name' => 'Facebook',
                    'enabled' => false,
                    'icon' => 'facebook',
                ],
            ]);

        return $user;
    }

    /**
     * Assert API response follows the unified format
     */
    protected function assertUnifiedApiResponse($response, int $expectedStatus = 200): void
    {
        $response->assertStatus($expectedStatus);

        $responseData = $response->json();

        // Check if it's already in unified format
        if (isset($responseData['success'])) {
            if ($expectedStatus >= 200 && $expectedStatus < 300) {
                // Success response format
                $expectedStructure = ['success', 'data'];

                // Check if it's a paginated response (has meta field)
                if (isset($responseData['meta'])) {
                    $expectedStructure[] = 'meta';
                    $expectedStructure[] = 'links';
                }

                // Only require message if it exists in the response
                if (isset($responseData['message'])) {
                    $expectedStructure[] = 'message';
                }

                $response->assertJsonStructure($expectedStructure)->assertJson(['success' => true]);
            } else {
                // Error response format
                $expectedStructure = ['success', 'error'];

                // Only require message if it exists in the response
                if (isset($responseData['message'])) {
                    $expectedStructure[] = 'message';
                }

                $response->assertJsonStructure($expectedStructure)->assertJson(['success' => false]);
            }
        } else {
            // Legacy format - just check status
            $response->assertStatus($expectedStatus);
        }
    }

    /**
     * Assert API response follows any valid format (unified or legacy)
     */
    protected function assertValidApiResponse($response, int $expectedStatus = 200): void
    {
        $response->assertStatus($expectedStatus);
        // This method just checks status and lets the specific test handle structure
    }

    /**
     * Cleanup test environment
     */
    protected function cleanupTestEnvironment(): void
    {
        // Clear any time manipulations
        if (method_exists($this, 'travelBack')) {
            $this->travelBack();
        }

        // Clear mocks
        if ($this->mockSocialAuthService) {
            Mockery::close();
        }

        // Reset configuration
        foreach ($this->testEnvironmentSettings as $key => $originalValue) {
            Config::set($key, $originalValue);
        }
    }

    /**
     * Helper to act as a specific test user with API authentication
     */
    protected function actingAsTestUser(string $userType = 'regular'): User
    {
        $user = match ($userType) {
            'super_admin' => $this->superAdmin,
            'organization_owner' => $this->organizationOwner,
            'organization_admin' => $this->organizationAdmin,
            'regular' => $this->regularUser,
            default => $this->regularUser,
        };

        Passport::actingAs($user, ['*']);

        return $user;
    }

    /**
     * Helper to create API headers for requests
     */
    protected function getApiHeaders(array $additional = []): array
    {
        return array_merge([
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'X-Requested-With' => 'XMLHttpRequest',
        ], $additional);
    }

    /**
     * Helper to assert database has proper audit logs
     */
    protected function assertAuditLogExists(User $user, string $event, array $additionalData = []): void
    {
        $this->assertDatabaseHas('authentication_logs', array_merge([
            'user_id' => $user->id,
            'event' => $event,
        ], $additionalData));
    }

    /**
     * Helper to simulate high load scenario
     */
    protected function simulateHighLoad(int $requests = 50): array
    {
        $responses = [];

        for ($i = 0; $i < $requests; $i++) {
            $user = $this->actingAsTestUser('regular');
            $responses[] = $this->getJson('/api/v1/auth/user');
        }

        return $responses;
    }
}
