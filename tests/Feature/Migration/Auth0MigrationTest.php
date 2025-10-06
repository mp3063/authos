<?php

namespace Tests\Feature\Migration;

use App\Jobs\ProcessAuth0MigrationJob;
use App\Models\Application;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class Auth0MigrationTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    public function test_performs_full_migration(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([
                [
                    'user_id' => 'auth0|123',
                    'email' => 'user1@example.com',
                    'name' => 'User One',
                    'email_verified' => true,
                ],
                [
                    'user_id' => 'auth0|456',
                    'email' => 'user2@example.com',
                    'name' => 'User Two',
                    'email_verified' => true,
                ],
            ], 200),
            '*.auth0.com/api/v2/clients*' => Http::response([
                [
                    'client_id' => 'auth0-client-1',
                    'name' => 'App One',
                    'callbacks' => ['https://app1.example.com/callback'],
                ],
            ], 200),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $migrationJob->refresh();

        $this->assertEquals('completed', $migrationJob->status);
        $this->assertEquals(2, User::where('organization_id', $this->organization->id)->count());
        $this->assertEquals(1, Application::where('organization_id', $this->organization->id)->count());
    }

    public function test_imports_users_from_auth0(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([
                [
                    'user_id' => 'auth0|123',
                    'email' => 'user@example.com',
                    'name' => 'Test User',
                    'email_verified' => true,
                    'created_at' => '2024-01-01T00:00:00Z',
                ],
            ], 200),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                    'migrate_users' => true,
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $this->assertDatabaseHas('users', [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_imports_applications_from_auth0(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/clients*' => Http::response([
                [
                    'client_id' => 'auth0-client-123',
                    'name' => 'My Application',
                    'description' => 'Test app',
                    'callbacks' => ['https://app.example.com/callback'],
                    'allowed_origins' => ['https://app.example.com'],
                ],
            ], 200),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                    'migrate_applications' => true,
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $this->assertDatabaseHas('applications', [
            'name' => 'My Application',
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_imports_organizations_from_auth0(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/organizations*' => Http::response([
                [
                    'id' => 'org_123',
                    'name' => 'Test Organization',
                    'display_name' => 'Test Org',
                    'metadata' => ['industry' => 'technology'],
                ],
            ], 200),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                    'migrate_organizations' => true,
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $this->assertDatabaseHas('organizations', [
            'name' => 'Test Organization',
        ]);
    }

    public function test_imports_roles_from_auth0(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/roles*' => Http::response([
                [
                    'id' => 'rol_123',
                    'name' => 'Developer',
                    'description' => 'Developer role',
                ],
                [
                    'id' => 'rol_456',
                    'name' => 'Manager',
                    'description' => 'Manager role',
                ],
            ], 200),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                    'migrate_roles' => true,
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $this->assertDatabaseHas('roles', [
            'name' => 'Developer',
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_handles_migration_rollback(): void
    {
        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'status' => 'completed',
                'migrated_data' => [
                    'users' => [1, 2, 3],
                    'applications' => [1],
                ],
            ]);

        User::factory()->for($this->organization)->count(3)->create();
        Application::factory()->forOrganization($this->organization)->create();

        $migrationJob->rollback();

        $this->assertEquals(0, User::where('organization_id', $this->organization->id)->count());
        $this->assertEquals(0, Application::where('organization_id', $this->organization->id)->count());
        $this->assertEquals('rolled_back', $migrationJob->fresh()->status);
    }

    public function test_handles_migration_errors(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([], 500),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $migrationJob->refresh();

        $this->assertEquals('failed', $migrationJob->status);
        $this->assertNotEmpty($migrationJob->error_message);
    }

    public function test_tracks_migration_progress(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response(
                array_map(fn ($i) => [
                    'user_id' => "auth0|{$i}",
                    'email' => "user{$i}@example.com",
                    'name' => "User {$i}",
                ], range(1, 50)),
                200
            ),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'total_items' => 50,
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $migrationJob->refresh();

        $this->assertEquals(50, $migrationJob->processed_items);
        $this->assertEquals(100, $migrationJob->progress_percentage);
    }

    public function test_validates_auth0_credentials_before_migration(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([], 401),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'invalid-token',
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $migrationJob->refresh();

        $this->assertEquals('failed', $migrationJob->status);
        $this->assertStringContainsString('authentication', strtolower($migrationJob->error_message ?? ''));
    }

    public function test_generates_migration_summary(): void
    {
        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'status' => 'completed',
                'stats' => [
                    'users_migrated' => 100,
                    'users_failed' => 5,
                    'applications_migrated' => 10,
                    'duration_seconds' => 120,
                ],
            ]);

        $summary = $migrationJob->getSummary();

        $this->assertStringContainsString('100 users migrated', $summary);
        $this->assertStringContainsString('5 failed', $summary);
        $this->assertStringContainsString('10 applications', $summary);
    }
}
