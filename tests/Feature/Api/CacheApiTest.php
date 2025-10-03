<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class CacheApiTest extends TestCase
{
    private Organization $organization;

    private User $superAdminUser;

    private User $adminUser;

    private User $regularUser;

    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();

        // Create required roles
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'super admin', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'organization admin', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'user', 'guard_name' => 'web']);

        // Create super admin user
        $this->superAdminUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $superAdminRole = Role::where('name', 'Super Admin')->where('guard_name', 'api')->first();
        $this->superAdminUser->setPermissionsTeamId($this->superAdminUser->organization_id);
        $this->superAdminUser->assignRole($superAdminRole);

        // Create organization admin user
        $this->adminUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $adminRole = Role::where('name', 'Organization Admin')->where('guard_name', 'api')->first();
        $this->adminUser->setPermissionsTeamId($this->adminUser->organization_id);
        $this->adminUser->assignRole($adminRole);

        // Create regular user
        $this->regularUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $userRole = Role::where('name', 'User')->where('guard_name', 'api')->first();
        $this->regularUser->setPermissionsTeamId($this->regularUser->organization_id);
        $this->regularUser->assignRole($userRole);

        // Create application for testing
        $this->application = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        // Clear any existing cache
        Cache::flush();
    }

    public function test_get_cache_stats_as_super_admin_succeeds(): void
    {
        Passport::actingAs($this->superAdminUser, ['system']);

        // Set up some test cache data
        Cache::put('test_key_1', 'value1', 3600);
        Cache::put('test_key_2', 'value2', 3600);
        Cache::increment('api_requests_total', 100);
        Cache::increment('cache_hits', 75);
        Cache::increment('cache_misses', 25);

        $response = $this->getJson('/api/v1/cache/stats');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'total_keys',
                'memory_usage',
                'hit_rate',
                'timestamp',
            ]);

        $responseData = $response->json();
        $this->assertIsArray($responseData);
        $this->assertArrayHasKey('memory_usage', $responseData);
        $this->assertArrayHasKey('total_keys', $responseData);
        $this->assertArrayHasKey('hit_rate', $responseData);
        $this->assertArrayHasKey('timestamp', $responseData);
    }

    public function test_get_cache_stats_as_regular_user_succeeds(): void
    {
        Passport::actingAs($this->regularUser, ['profile']);

        $response = $this->getJson('/api/v1/cache/stats');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'total_keys',
                'memory_usage',
                'hit_rate',
                'timestamp',
            ]);

        $responseData = $response->json();
        $this->assertIsArray($responseData);
        $this->assertArrayHasKey('memory_usage', $responseData);
        $this->assertArrayHasKey('total_keys', $responseData);
    }

    public function test_get_cache_stats_requires_authentication(): void
    {
        $response = $this->getJson('/api/v1/cache/stats');

        $response->assertStatus(401)
            ->assertJson(['message' => 'Unauthenticated.']);
    }

    public function test_clear_all_cache_as_super_admin_succeeds(): void
    {
        Passport::actingAs($this->superAdminUser, ['system']);

        // Set up some test cache data
        Cache::put('test_key_1', 'value1', 3600);
        Cache::put('test_key_2', 'value2', 3600);

        // Verify cache has data
        $this->assertTrue(Cache::has('test_key_1'));
        $this->assertTrue(Cache::has('test_key_2'));

        $response = $this->deleteJson('/api/v1/cache/clear-all');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'All caches cleared successfully',
            ]);

        // Verify cache was cleared
        $this->assertFalse(Cache::has('test_key_1'));
        $this->assertFalse(Cache::has('test_key_2'));
    }

    public function test_clear_all_cache_as_admin_succeeds(): void
    {
        Passport::actingAs($this->adminUser, ['system']);

        // Set up some test cache data
        Cache::put('admin_test_key', 'value1', 3600);

        // Verify cache has data
        $this->assertTrue(Cache::has('admin_test_key'));

        $response = $this->deleteJson('/api/v1/cache/clear-all');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'All caches cleared successfully',
            ]);

        // Verify cache was cleared
        $this->assertFalse(Cache::has('admin_test_key'));
    }

    public function test_clear_user_cache_succeeds(): void
    {
        Passport::actingAs($this->superAdminUser, ['system']);

        // Set up user-specific cache data
        $userCacheKey = "user_{$this->regularUser->id}_profile";
        Cache::put($userCacheKey, ['name' => $this->regularUser->name], 3600);
        Cache::put('other_cache', 'other_value', 3600);

        // Verify cache has data
        $this->assertTrue(Cache::has($userCacheKey));

        $response = $this->deleteJson('/api/v1/cache/clear-user');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'User caches cleared successfully',
            ]);

        // Verify general cache remains (since this is a stub implementation)
        $this->assertTrue(Cache::has('other_cache'));
    }

    public function test_cache_endpoints_require_authentication(): void
    {
        $endpoints = [
            ['GET', '/api/v1/cache/stats'],
            ['DELETE', '/api/v1/cache/clear-all'],
            ['DELETE', '/api/v1/cache/clear-user'],
        ];

        foreach ($endpoints as $endpoint) {
            [$method, $url] = $endpoint;

            $response = $this->json($method, $url);
            $response->assertStatus(401, "Endpoint {$method} {$url} should require authentication");
        }
    }

    public function test_cache_stats_includes_basic_information(): void
    {
        Passport::actingAs($this->superAdminUser, ['system']);

        // Set up cache data
        Cache::put('test_stats_key', 'test_value', 3600);

        $response = $this->getJson('/api/v1/cache/stats');

        $response->assertStatus(200);

        $data = $response->json();

        // Basic cache stats should always be present
        $this->assertArrayHasKey('memory_usage', $data);
        $this->assertArrayHasKey('total_keys', $data);
        $this->assertArrayHasKey('hit_rate', $data);
        $this->assertArrayHasKey('timestamp', $data);

        // Verify data types
        $this->assertIsString($data['memory_usage']);
        $this->assertIsInt($data['total_keys']);
        $this->assertIsString($data['hit_rate']);
    }

    public function test_all_cache_operations_work_together(): void
    {
        Passport::actingAs($this->superAdminUser, ['system']);

        // Set up test cache
        Cache::put('test_integration_key', 'test_data', 3600);
        $this->assertTrue(Cache::has('test_integration_key'));

        // Get stats - should work
        $statsResponse = $this->getJson('/api/v1/cache/stats');
        $statsResponse->assertStatus(200);

        // Clear user cache - should work
        $clearUserResponse = $this->deleteJson('/api/v1/cache/clear-user');
        $clearUserResponse->assertStatus(200);

        // Clear all cache - should work and actually clear cache
        $clearAllResponse = $this->deleteJson('/api/v1/cache/clear-all');
        $clearAllResponse->assertStatus(200);

        // Verify cache was cleared
        $this->assertFalse(Cache::has('test_integration_key'));
    }
}
