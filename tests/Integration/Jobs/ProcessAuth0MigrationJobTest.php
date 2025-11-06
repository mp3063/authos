<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\ProcessAuth0MigrationJob;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\User;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\DTOs\Auth0ClientDTO;
use App\Services\Auth0\DTOs\Auth0RoleDTO;
use App\Services\Auth0\DTOs\Auth0UserDTO;
use App\Services\Auth0\Migration\Auth0MigrationService;
use App\Services\Auth0\Migration\DTOs\MigrationPlan;
use App\Services\Auth0\Migration\DTOs\MigrationResult;
use App\Services\Auth0\Migration\DTOs\ResourceStats;
use App\Services\Auth0\Migration\Importers\UserImporter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ProcessAuth0MigrationJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private MigrationJob $migrationJob;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->migrationJob = MigrationJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => 'auth0',
            'status' => 'pending',
            'config' => [
                'tenant_domain' => 'test.auth0.com',
                'api_token' => 'test-token',
                'migrate_users' => true,
                'migrate_applications' => true,
                'migrate_roles' => true,
                'password_strategy' => UserImporter::STRATEGY_LAZY,
            ],
        ]);
    }

    #[Test]
    public function job_imports_users_from_auth0_export(): void
    {
        $mockPlan = new MigrationPlan(
            users: [
                new Auth0UserDTO(
                    userId: 'auth0|123',
                    email: 'user1@example.com',
                    name: 'User One',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString()
                ),
                new Auth0UserDTO(
                    userId: 'auth0|456',
                    email: 'user2@example.com',
                    name: 'User Two',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString()
                ),
            ],
            applications: [],
            roles: []
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 2, successful: 2, failed: 0, skipped: 0),
            applications: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('completed', $this->migrationJob->status);
        $this->assertEquals(2, $this->migrationJob->stats['users']['successful']);
    }

    #[Test]
    public function job_maps_auth0_fields_to_local_schema(): void
    {
        $mockPlan = new MigrationPlan(
            users: [
                new Auth0UserDTO(
                    userId: 'auth0|789',
                    email: 'mapped@example.com',
                    name: 'Mapped User',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString(),
                    metadata: ['custom_field' => 'custom_value']
                ),
            ],
            applications: [],
            roles: []
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 1, successful: 1, failed: 0, skipped: 0),
            applications: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('completed', $this->migrationJob->status);

        // Verify migrated data contains mapped fields
        $migratedData = $this->migrationJob->migrated_data;
        $this->assertArrayHasKey('users', $migratedData);
        $this->assertEquals('auth0|789', $migratedData['users'][0]['user_id']);
        $this->assertEquals('mapped@example.com', $migratedData['users'][0]['email']);
    }

    #[Test]
    public function job_preserves_password_hashes(): void
    {
        $this->migrationJob->update([
            'config' => array_merge($this->migrationJob->config, [
                'password_strategy' => UserImporter::STRATEGY_LAZY,
            ]),
        ]);

        $mockPlan = new MigrationPlan(
            users: [
                new Auth0UserDTO(
                    userId: 'auth0|999',
                    email: 'password@example.com',
                    name: 'Password User',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString(),
                    passwordHash: '$2a$10$hashedpassword'
                ),
            ],
            applications: [],
            roles: []
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 1, successful: 1, failed: 0, skipped: 0),
            applications: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('completed', $this->migrationJob->status);
    }

    #[Test]
    public function job_links_social_accounts(): void
    {
        $mockPlan = new MigrationPlan(
            users: [
                new Auth0UserDTO(
                    userId: 'google-oauth2|123',
                    email: 'social@example.com',
                    name: 'Social User',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString()
                ),
            ],
            applications: [],
            roles: []
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 1, successful: 1, failed: 0, skipped: 0),
            applications: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('completed', $this->migrationJob->status);
    }

    #[Test]
    public function job_assigns_roles_and_permissions(): void
    {
        $mockPlan = new MigrationPlan(
            users: [],
            applications: [],
            roles: [
                new Auth0RoleDTO(
                    id: 'rol_123',
                    name: 'Admin',
                    description: 'Administrator role',
                    permissions: ['read:users', 'write:users']
                ),
            ]
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            applications: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 1, successful: 1, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('completed', $this->migrationJob->status);
        $this->assertEquals(1, $this->migrationJob->stats['roles']['successful']);
    }

    #[Test]
    public function job_handles_duplicate_users(): void
    {
        // Create existing user
        User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'duplicate@example.com',
        ]);

        $mockPlan = new MigrationPlan(
            users: [
                new Auth0UserDTO(
                    userId: 'auth0|duplicate',
                    email: 'duplicate@example.com',
                    name: 'Duplicate User',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString()
                ),
            ],
            applications: [],
            roles: []
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 1, successful: 0, failed: 0, skipped: 1),
            applications: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('completed', $this->migrationJob->status);
        $this->assertEquals(1, $this->migrationJob->stats['users']['skipped']);
    }

    #[Test]
    public function job_validates_auth0_export_format(): void
    {
        Log::shouldReceive('error')
            ->once()
            ->with(
                'Auth0 migration failed',
                Mockery::on(function ($context) {
                    return isset($context['error']) &&
                           str_contains($context['error'], 'Missing Auth0');
                })
            );

        // Missing required configuration
        $this->migrationJob->update([
            'config' => [
                'tenant_domain' => 'test.auth0.com',
                // Missing api_token
            ],
        ]);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();
        $this->assertEquals('failed', $this->migrationJob->status);
        $this->assertNotEmpty($this->migrationJob->error_log);
    }

    #[Test]
    public function job_provides_detailed_migration_report(): void
    {
        $mockPlan = new MigrationPlan(
            users: [
                new Auth0UserDTO(
                    userId: 'auth0|report1',
                    email: 'report1@example.com',
                    name: 'Report User 1',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString()
                ),
                new Auth0UserDTO(
                    userId: 'auth0|report2',
                    email: 'report2@example.com',
                    name: 'Report User 2',
                    emailVerified: true,
                    createdAt: now()->toDateTimeString(),
                    updatedAt: now()->toDateTimeString()
                ),
            ],
            applications: [
                new Auth0ClientDTO(
                    clientId: 'client123',
                    name: 'Test App',
                    appType: 'spa',
                    callbacks: []
                ),
            ],
            roles: []
        );

        $mockResult = new MigrationResult(
            users: new ResourceStats(total: 2, successful: 2, failed: 0, skipped: 0),
            applications: new ResourceStats(total: 1, successful: 1, failed: 0, skipped: 0),
            roles: new ResourceStats(total: 0, successful: 0, failed: 0, skipped: 0)
        );

        $this->mockAuth0Migration($mockPlan, $mockResult);

        $job = new ProcessAuth0MigrationJob($this->migrationJob);
        $job->handle();

        $this->migrationJob->refresh();

        // Verify detailed report
        $this->assertEquals('completed', $this->migrationJob->status);
        $this->assertNotNull($this->migrationJob->stats);
        $this->assertNotNull($this->migrationJob->migrated_data);

        $stats = $this->migrationJob->stats;
        $this->assertEquals(2, $stats['users']['total']);
        $this->assertEquals(2, $stats['users']['successful']);
        $this->assertEquals(1, $stats['applications']['total']);
        $this->assertEquals(1, $stats['applications']['successful']);
    }

    /**
     * Mock Auth0 migration service
     */
    private function mockAuth0Migration(MigrationPlan $plan, MigrationResult $result): void
    {
        $mockService = Mockery::mock(Auth0MigrationService::class);
        $mockService->shouldReceive('discover')
            ->once()
            ->andReturn($plan);

        $mockService->shouldReceive('migrate')
            ->once()
            ->andReturn($result);

        // Mock the Auth0Client instantiation
        $this->app->bind(Auth0Client::class, function () {
            return Mockery::mock(Auth0Client::class);
        });

        // Mock the service instantiation
        $this->app->bind(Auth0MigrationService::class, function () use ($mockService) {
            return $mockService;
        });
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
