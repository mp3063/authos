<?php

namespace Tests\Unit\Services\Migration;

use App\Models\Organization;
use App\Services\Migration\Auth0MigrationService;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class Auth0MigrationServiceTest extends TestCase
{
    private Auth0MigrationService $service;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new Auth0MigrationService;
        $this->organization = Organization::factory()->create();
    }

    public function test_discovers_auth0_tenant_configuration(): void
    {
        Http::fake([
            'tenant.auth0.com/*' => Http::response([
                'tenant' => 'test-tenant',
                'users_count' => 100,
                'applications_count' => 5,
                'connections' => ['Username-Password-Authentication', 'google-oauth2'],
            ], 200),
        ]);

        $config = $this->service->discoverTenant('tenant.auth0.com', 'api-token');

        $this->assertEquals('test-tenant', $config['tenant']);
        $this->assertEquals(100, $config['users_count']);
        $this->assertContains('google-oauth2', $config['connections']);
    }

    public function test_creates_migration_plan(): void
    {
        $tenantConfig = [
            'users_count' => 150,
            'applications_count' => 3,
            'connections' => ['Username-Password-Authentication'],
        ];

        $plan = $this->service->createMigrationPlan($this->organization, $tenantConfig);

        $this->assertArrayHasKey('steps', $plan);
        $this->assertArrayHasKey('estimated_time', $plan);
        $this->assertArrayHasKey('resources', $plan);
        $this->assertContains('users', $plan['resources']);
        $this->assertContains('applications', $plan['resources']);
    }

    public function test_performs_dry_run(): void
    {
        Http::fake([
            '*.auth0.com/*' => Http::response([
                'users' => [
                    ['email' => 'user1@example.com', 'name' => 'User 1'],
                    ['email' => 'user2@example.com', 'name' => 'User 2'],
                ],
                'clients' => [
                    ['name' => 'App 1', 'client_id' => 'client-1'],
                ],
            ], 200),
        ]);

        $result = $this->service->dryRun('tenant.auth0.com', 'api-token', $this->organization);

        $this->assertArrayHasKey('users', $result);
        $this->assertArrayHasKey('applications', $result);
        $this->assertArrayHasKey('issues', $result);
        $this->assertCount(2, $result['users']);
        $this->assertCount(1, $result['applications']);
    }

    public function test_validates_auth0_api_token(): void
    {
        Http::fake([
            '*.auth0.com/*' => Http::response([], 401),
        ]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid Auth0 API token');

        $this->service->validateApiToken('tenant.auth0.com', 'invalid-token');
    }

    public function test_validates_tenant_domain(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid Auth0 tenant domain');

        $this->service->discoverTenant('invalid-domain', 'api-token');
    }

    public function test_detects_incompatible_features(): void
    {
        $tenantConfig = [
            'connections' => ['auth0', 'custom-db', 'enterprise-saml'],
            'rules' => ['custom-rule-1'],
            'hooks' => ['pre-registration'],
        ];

        $issues = $this->service->detectIncompatibilities($tenantConfig);

        $this->assertNotEmpty($issues);
        $this->assertContains('custom-db', array_column($issues, 'feature'));
    }

    public function test_estimates_migration_time(): void
    {
        $tenantConfig = [
            'users_count' => 1000,
            'applications_count' => 10,
            'connections' => ['Username-Password-Authentication', 'google-oauth2'],
        ];

        $estimatedMinutes = $this->service->estimateMigrationTime($tenantConfig);

        $this->assertIsInt($estimatedMinutes);
        $this->assertGreaterThan(0, $estimatedMinutes);
    }

    public function test_maps_auth0_connections_to_providers(): void
    {
        $connections = [
            'Username-Password-Authentication',
            'google-oauth2',
            'github',
            'facebook',
        ];

        $mapping = $this->service->mapConnectionsToProviders($connections);

        $this->assertArrayHasKey('database', $mapping);
        $this->assertArrayHasKey('social', $mapping);
        $this->assertContains('google', $mapping['social']);
        $this->assertContains('github', $mapping['social']);
    }

    public function test_generates_migration_report(): void
    {
        $migrationResults = [
            'users' => ['migrated' => 95, 'failed' => 5, 'total' => 100],
            'applications' => ['migrated' => 5, 'failed' => 0, 'total' => 5],
            'connections' => ['migrated' => 2, 'failed' => 0, 'total' => 2],
        ];

        $report = $this->service->generateMigrationReport($migrationResults);

        $this->assertStringContainsString('95 users migrated successfully', $report);
        $this->assertStringContainsString('5 users failed', $report);
        $this->assertStringContainsString('5 applications migrated', $report);
    }

    public function test_validates_migration_prerequisites(): void
    {
        $prerequisites = $this->service->validatePrerequisites($this->organization);

        $this->assertArrayHasKey('database', $prerequisites);
        $this->assertArrayHasKey('storage', $prerequisites);
        $this->assertArrayHasKey('permissions', $prerequisites);
    }
}
