<?php

namespace Tests\Integration;

use App\Jobs\ProcessAuth0MigrationJob;
use App\Models\Application;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class MigrationIntegrationTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    public function test_complete_auth0_migration(): void
    {
        // Mock Auth0 API responses
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([
                [
                    'user_id' => 'auth0|user1',
                    'email' => 'user1@example.com',
                    'name' => 'User One',
                    'email_verified' => true,
                    'identities' => [
                        [
                            'provider' => 'auth0',
                            'connection' => 'Username-Password-Authentication',
                        ],
                    ],
                    'app_metadata' => ['roles' => ['user']],
                ],
                [
                    'user_id' => 'google-oauth2|user2',
                    'email' => 'user2@example.com',
                    'name' => 'User Two',
                    'email_verified' => true,
                    'identities' => [
                        [
                            'provider' => 'google-oauth2',
                            'user_id' => 'google-123456',
                            'connection' => 'google-oauth2',
                        ],
                    ],
                ],
                [
                    'user_id' => 'auth0|admin',
                    'email' => 'admin@example.com',
                    'name' => 'Admin User',
                    'email_verified' => true,
                    'app_metadata' => ['roles' => ['admin']],
                ],
            ], 200),
            '*.auth0.com/api/v2/clients*' => Http::response([
                [
                    'client_id' => 'auth0-client-1',
                    'name' => 'Web Application',
                    'description' => 'Main web app',
                    'app_type' => 'regular_web',
                    'callbacks' => [
                        'https://app.example.com/callback',
                        'https://app.example.com/silent-callback',
                    ],
                    'allowed_origins' => ['https://app.example.com'],
                    'web_origins' => ['https://app.example.com'],
                ],
                [
                    'client_id' => 'auth0-client-2',
                    'name' => 'Mobile Application',
                    'app_type' => 'native',
                    'callbacks' => ['myapp://callback'],
                ],
            ], 200),
            '*.auth0.com/api/v2/roles*' => Http::response([
                [
                    'id' => 'rol_123',
                    'name' => 'User',
                    'description' => 'Regular user',
                ],
                [
                    'id' => 'rol_456',
                    'name' => 'Admin',
                    'description' => 'Administrator',
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
                    'migrate_applications' => true,
                    'migrate_roles' => true,
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $migrationJob->refresh();

        // Verify migration completed successfully
        $this->assertEquals('completed', $migrationJob->status);

        // Verify users were migrated
        $this->assertEquals(3, User::where('organization_id', $this->organization->id)->count());

        $user1 = User::where('email', 'user1@example.com')->first();
        $this->assertNotNull($user1);
        $this->assertEquals('User One', $user1->name);
        $this->assertNotNull($user1->email_verified_at);

        // Verify social account was created
        $user2 = User::where('email', 'user2@example.com')->first();
        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $user2->id,
            'provider' => 'google',
            'provider_user_id' => 'google-123456',
        ]);

        // Verify applications were migrated
        $this->assertEquals(2, Application::where('organization_id', $this->organization->id)->count());

        $app1 = Application::where('name', 'Web Application')->first();
        $this->assertNotNull($app1);
        $this->assertContains('https://app.example.com/callback', $app1->redirect_uris);

        // Verify roles were migrated
        $this->assertDatabaseHas('roles', [
            'name' => 'User',
            'organization_id' => $this->organization->id,
        ]);
        $this->assertDatabaseHas('roles', [
            'name' => 'Admin',
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_migration_validation(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([
                ['email' => 'valid@example.com', 'name' => 'Valid User'],
                ['email' => 'invalid-email', 'name' => 'Invalid User'],
                ['name' => 'No Email User'],
            ], 200),
        ]);

        $migrationJob = MigrationJob::factory()
            ->for($this->organization)
            ->create([
                'source' => 'auth0',
                'config' => [
                    'tenant_domain' => 'tenant.auth0.com',
                    'api_token' => 'test-token',
                    'validate_before_import' => true,
                ],
            ]);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $migrationJob->refresh();

        $this->assertEquals('completed_with_errors', $migrationJob->status);

        // Only valid user should be imported
        $this->assertEquals(1, User::where('organization_id', $this->organization->id)->count());
        $this->assertDatabaseHas('users', ['email' => 'valid@example.com']);

        // Validation errors should be recorded
        $this->assertNotEmpty($migrationJob->validation_errors);
    }

    public function test_migration_rollback(): void
    {
        // First, complete a migration
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([
                ['user_id' => 'auth0|1', 'email' => 'user1@example.com', 'name' => 'User 1'],
                ['user_id' => 'auth0|2', 'email' => 'user2@example.com', 'name' => 'User 2'],
            ], 200),
            '*.auth0.com/api/v2/clients*' => Http::response([
                ['client_id' => 'client-1', 'name' => 'App 1'],
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

        // Verify data was migrated
        $this->assertEquals(2, User::where('organization_id', $this->organization->id)->count());
        $this->assertEquals(1, Application::where('organization_id', $this->organization->id)->count());

        // Now rollback the migration
        $migrationJob->refresh();
        $migrationJob->rollback();

        // Verify all migrated data was removed
        $this->assertEquals(0, User::where('organization_id', $this->organization->id)->count());
        $this->assertEquals(0, Application::where('organization_id', $this->organization->id)->count());

        $migrationJob->refresh();
        $this->assertEquals('rolled_back', $migrationJob->status);
    }

    public function test_migration_handles_rate_limiting(): void
    {
        // Simulate Auth0 rate limiting
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::sequence()
                ->push([], 429, ['X-RateLimit-Remaining' => '0', 'X-RateLimit-Reset' => time() + 2])
                ->push([
                    ['user_id' => 'auth0|1', 'email' => 'user@example.com', 'name' => 'User'],
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

        $startTime = microtime(true);

        $processor = new ProcessAuth0MigrationJob($migrationJob);
        $processor->handle();

        $duration = microtime(true) - $startTime;

        $migrationJob->refresh();

        // Should handle rate limiting and complete successfully
        $this->assertEquals('completed', $migrationJob->status);

        // Should have waited for rate limit reset
        $this->assertGreaterThan(2, $duration);
    }

    public function test_migration_preserves_user_metadata(): void
    {
        Http::fake([
            '*.auth0.com/api/v2/users*' => Http::response([
                [
                    'user_id' => 'auth0|1',
                    'email' => 'user@example.com',
                    'name' => 'Test User',
                    'user_metadata' => [
                        'phone' => '+1234567890',
                        'preferences' => ['theme' => 'dark'],
                    ],
                    'app_metadata' => [
                        'subscription' => 'premium',
                        'trial_ends_at' => '2024-12-31',
                    ],
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

        $user = User::where('email', 'user@example.com')->first();

        $this->assertNotNull($user->metadata);
        $this->assertEquals('+1234567890', $user->metadata['phone'] ?? null);
        $this->assertEquals('premium', $user->metadata['subscription'] ?? null);
    }

    public function test_migration_summary_report(): void
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
            '*.auth0.com/api/v2/clients*' => Http::response([
                ['client_id' => 'client-1', 'name' => 'App 1'],
                ['client_id' => 'client-2', 'name' => 'App 2'],
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
        $summary = $migrationJob->getSummary();

        $this->assertStringContainsString('50 users', strtolower($summary));
        $this->assertStringContainsString('2 applications', strtolower($summary));
        $this->assertStringContainsString('completed', strtolower($summary));
    }
}
