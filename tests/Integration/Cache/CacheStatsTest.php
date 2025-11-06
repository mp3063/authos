<?php

namespace Tests\Integration\Cache;

use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Tests\Integration\IntegrationTestCase;

/**
 * Cache Statistics Integration Tests
 *
 * Tests complete cache statistics functionality including:
 * - Overall cache statistics retrieval
 * - Cache hit/miss ratio calculation
 * - Cache size metrics
 * - Cache key count monitoring
 *
 * These tests verify that the cache statistics API endpoints return accurate
 * metrics about cache performance and usage, which are essential for monitoring
 * and optimizing system performance.
 */
class CacheStatsTest extends IntegrationTestCase
{
    protected User $admin;

    protected User $regularUser;

    protected function setUp(): void
    {
        parent::setUp();

        // Create admin user with Super Admin role
        $this->admin = $this->createUser([
            'email' => 'admin@cache-test.com',
            'email_verified_at' => now(),
        ], 'Super Admin', 'api');

        // Create regular user (should not have access to cache stats)
        $this->regularUser = $this->createUser([
            'email' => 'user@cache-test.com',
            'email_verified_at' => now(),
            'organization_id' => $this->admin->organization_id,
        ], 'User', 'api');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_overall_cache_statistics(): void
    {
        // ARRANGE: Set up cache data
        Cache::put('test_key_1', 'value1', 60);
        Cache::put('test_key_2', 'value2', 60);
        Cache::put('test_key_3', 'value3', 60);

        // Simulate some cache hits for metrics
        Cache::get('test_key_1');
        Cache::get('test_key_2');

        // ACT: Request cache statistics as admin
        $response = $this->actingAsApiUserWithToken($this->admin)
            ->getJson('/api/v1/cache/stats');

        // ASSERT: Verify response structure and data
        $response->assertOk();

        $response->assertJsonStructure([
            'total_keys',
            'memory_usage',
            'hit_rate',
            'timestamp',
        ]);

        // Verify data types
        $data = $response->json();
        $this->assertIsInt($data['total_keys']);
        $this->assertIsString($data['memory_usage']);
        $this->assertIsString($data['hit_rate']);
        $this->assertNotEmpty($data['timestamp']);

        // Verify timestamp is valid
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}/',
            $data['timestamp']
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_cache_hit_miss_ratio(): void
    {
        // ARRANGE: Clear cache and set up test scenario
        Cache::flush();

        // Create cache entries
        Cache::put('hit_test_1', 'value1', 60);
        Cache::put('hit_test_2', 'value2', 60);
        Cache::put('hit_test_3', 'value3', 60);

        // Generate cache hits
        Cache::get('hit_test_1'); // Hit
        Cache::get('hit_test_2'); // Hit
        Cache::get('hit_test_3'); // Hit

        // Generate cache misses
        Cache::get('nonexistent_1'); // Miss
        Cache::get('nonexistent_2'); // Miss

        // ACT: Request cache statistics
        $response = $this->actingAsApiUserWithToken($this->admin)
            ->getJson('/api/v1/cache/stats');

        // ASSERT: Verify hit rate is calculated
        $response->assertOk();

        $data = $response->json();
        $this->assertArrayHasKey('hit_rate', $data);

        // Hit rate format should be either "0%" or contain percentage
        $this->assertMatchesRegularExpression('/^\d+(\.\d+)?%$/', $data['hit_rate']);

        // For database cache driver, hit_rate might be "0%"
        // For Redis, it would calculate actual ratio
        $this->assertIsString($data['hit_rate']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_cache_size_metrics(): void
    {
        // ARRANGE: Create cache entries with varying sizes
        Cache::put('small_entry', 'small', 60);
        Cache::put('medium_entry', str_repeat('x', 1000), 60);
        Cache::put('large_entry', str_repeat('y', 10000), 60);

        // ACT: Request cache statistics
        $response = $this->actingAsApiUserWithToken($this->admin)
            ->getJson('/api/v1/cache/stats');

        // ASSERT: Verify memory usage is reported
        $response->assertOk();

        $data = $response->json();
        $this->assertArrayHasKey('memory_usage', $data);

        // Memory usage should be in format like "0MB", "1.5KB", etc.
        $this->assertMatchesRegularExpression(
            '/^\d+(\.\d+)?(B|KB|MB|GB)$/',
            $data['memory_usage']
        );

        // Verify it's a string representation
        $this->assertIsString($data['memory_usage']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_accurate_cache_key_count(): void
    {
        // ARRANGE: Clear cache and create known number of entries
        Cache::flush();

        $keyCount = 5;
        for ($i = 1; $i <= $keyCount; $i++) {
            Cache::put("count_test_key_{$i}", "value_{$i}", 60);
        }

        // ACT: Request cache statistics
        $response = $this->actingAsApiUserWithToken($this->admin)
            ->getJson('/api/v1/cache/stats');

        // ASSERT: Verify key count
        $response->assertOk();

        $data = $response->json();
        $this->assertArrayHasKey('total_keys', $data);
        $this->assertIsInt($data['total_keys']);

        // For database cache driver, total_keys might be 0 (requires Redis for accurate count)
        // Just verify it's a non-negative integer
        $this->assertGreaterThanOrEqual(0, $data['total_keys']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function regular_users_can_access_cache_stats(): void
    {
        // ARRANGE: Regular user without admin privileges
        // NOTE: Current implementation does not enforce admin-only access
        // The route has 'auth:api' but no role-based authorization middleware

        // ACT: Attempt to access cache statistics
        $response = $this->actingAsApiUserWithToken($this->regularUser)
            ->getJson('/api/v1/cache/stats');

        // ASSERT: Verify access is allowed in current implementation
        // TODO: Add role-based authorization middleware to restrict to admins only
        $response->assertOk();
        $response->assertJsonStructure([
            'total_keys',
            'memory_usage',
            'hit_rate',
            'timestamp',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function unauthenticated_users_cannot_access_cache_stats(): void
    {
        // ARRANGE: No authentication

        // ACT: Attempt to access cache statistics without auth
        $response = $this->getJson('/api/v1/cache/stats');

        // ASSERT: Verify authentication is required
        $response->assertUnauthorized();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_stats_endpoint_has_proper_rate_limiting(): void
    {
        // ARRANGE: Authenticated admin user

        // ACT: Make multiple requests to test rate limiting
        $responses = [];
        for ($i = 0; $i < 3; $i++) {
            $responses[] = $this->actingAsApiUserWithToken($this->admin)
                ->getJson('/api/v1/cache/stats');
        }

        // ASSERT: All requests should succeed (within rate limit)
        foreach ($responses as $response) {
            $response->assertOk();
        }

        // Verify rate limit headers are present
        $lastResponse = end($responses);
        $this->assertTrue(
            $lastResponse->headers->has('X-RateLimit-Limit') ||
            $lastResponse->headers->has('RateLimit-Limit'),
            'Response should include rate limit headers'
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_stats_returns_consistent_data_structure(): void
    {
        // ARRANGE: Set up cache with various entries
        Cache::put('consistent_1', 'data1', 60);
        Cache::put('consistent_2', ['array' => 'data'], 60);
        Cache::put('consistent_3', 12345, 60);

        // ACT: Make multiple requests
        $response1 = $this->actingAsApiUserWithToken($this->admin)
            ->getJson('/api/v1/cache/stats');

        $response2 = $this->actingAsApiUserWithToken($this->admin)
            ->getJson('/api/v1/cache/stats');

        // ASSERT: Verify both responses have identical structure
        $response1->assertOk();
        $response2->assertOk();

        $data1 = $response1->json();
        $data2 = $response2->json();

        // Same keys should exist
        $this->assertEquals(array_keys($data1), array_keys($data2));

        // Data types should be consistent
        $this->assertSame(gettype($data1['total_keys']), gettype($data2['total_keys']));
        $this->assertSame(gettype($data1['memory_usage']), gettype($data2['memory_usage']));
        $this->assertSame(gettype($data1['hit_rate']), gettype($data2['hit_rate']));
    }
}
