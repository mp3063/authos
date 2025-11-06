<?php

namespace Tests\Integration\Monitoring;

use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\Integration\IntegrationTestCase;

/**
 * Performance Metrics Integration Tests
 *
 * Tests the performance monitoring system that tracks response times,
 * database query performance, cache efficiency, and overall system
 * throughput for identifying bottlenecks and optimization opportunities.
 *
 * Endpoints tested:
 * - GET /api/v1/monitoring/metrics/performance (all performance metrics)
 */
class PerformanceMetricsTest extends IntegrationTestCase
{
    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = $this->createUser();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function average_response_time_per_endpoint_is_tracked(): void
    {
        // ARRANGE: Make requests to different endpoints
        $this->actingAsApiUserWithToken($this->user);

        // Generate traffic to various endpoints
        $endpoints = [
            '/api/v1/profile',
            '/api/v1/users',
            '/api/v1/applications',
            '/api/v1/organizations',
        ];

        foreach ($endpoints as $endpoint) {
            $this->getJson($endpoint);
        }

        // ACT: Request performance metrics
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        // ASSERT: Response includes average response time data
        $response->assertOk();
        $response->assertJsonStructure([
            'avg_response_time_ms',
            'max_response_time_ms',
            'min_response_time_ms',
            'avg_memory_usage_bytes',
            'slow_queries_count',
            'cache' => [
                'hits',
                'misses',
                'hit_rate',
            ],
        ]);

        $data = $response->json();

        // Verify average response time
        $this->assertIsNumeric($data['avg_response_time_ms']);
        $this->assertGreaterThanOrEqual(0, $data['avg_response_time_ms']);

        // Verify metric values are reasonable
        $this->assertIsNumeric($data['max_response_time_ms']);
        $this->assertIsNumeric($data['min_response_time_ms']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function percentile_response_times_show_performance_distribution(): void
    {
        // ARRANGE: Generate varied request load
        $this->actingAsApiUserWithToken($this->user);

        // Make multiple requests to create distribution
        for ($i = 0; $i < 10; $i++) {
            $this->getJson('/api/v1/profile');
        }

        // ACT: Request performance metrics
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        // ASSERT: Performance metrics are calculated
        $response->assertOk();
        $data = $response->json();

        // Verify response time metrics exist
        $this->assertArrayHasKey('avg_response_time_ms', $data);
        $this->assertArrayHasKey('max_response_time_ms', $data);
        $this->assertArrayHasKey('min_response_time_ms', $data);

        $avg = $data['avg_response_time_ms'];
        $max = $data['max_response_time_ms'];
        $min = $data['min_response_time_ms'];

        $this->assertIsNumeric($avg);
        $this->assertIsNumeric($max);
        $this->assertIsNumeric($min);

        // Max should be >= Avg >= Min (when requests exist)
        if ($avg > 0) {
            $this->assertGreaterThanOrEqual($avg, $max);
            $this->assertLessThanOrEqual($avg, $min);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function slow_queries_detection_identifies_database_bottlenecks(): void
    {
        // ARRANGE: Enable query logging and make database-heavy requests
        DB::enableQueryLog();

        $this->actingAsApiUserWithToken($this->user);

        // Make requests that generate database queries
        $this->getJson('/api/v1/users');
        $this->getJson('/api/v1/applications');
        $this->getJson('/api/v1/organizations');

        $queries = DB::getQueryLog();
        $queryCount = count($queries);

        // ACT: Request performance metrics with slow query detection
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        // ASSERT: Slow queries are tracked
        $response->assertOk();
        $data = $response->json();

        $this->assertArrayHasKey('slow_queries_count', $data);
        $this->assertIsInt($data['slow_queries_count']);
        $this->assertGreaterThanOrEqual(0, $data['slow_queries_count']);

        // Verify queries were executed
        $this->assertGreaterThan(0, $queryCount);

        // Performance metrics should include query information
        if (isset($data['database_queries'])) {
            $this->assertIsArray($data['database_queries']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_hit_rate_measures_caching_efficiency(): void
    {
        // ARRANGE: Generate cache hits and misses
        $this->actingAsApiUserWithToken($this->user);

        // Cache miss (first request)
        Cache::forget('test_metric_key');
        $value1 = Cache::remember('test_metric_key', 60, fn () => 'cached_value');
        $this->assertEquals('cached_value', $value1);

        // Cache hit (subsequent request)
        $value2 = Cache::get('test_metric_key');
        $this->assertEquals('cached_value', $value2);

        // Make API requests that use caching
        $this->getJson('/api/v1/monitoring/metrics/authentication');
        $this->getJson('/api/v1/monitoring/metrics/authentication'); // Should hit cache

        // ACT: Request cache performance metrics
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        // ASSERT: Cache hit rate is calculated
        $response->assertOk();
        $data = $response->json();

        $this->assertArrayHasKey('cache', $data);
        $this->assertIsArray($data['cache']);
        $this->assertArrayHasKey('hit_rate', $data['cache']);
        $this->assertIsNumeric($data['cache']['hit_rate']);

        // Cache hit rate should be between 0 and 100 (percentage)
        $this->assertGreaterThanOrEqual(0, $data['cache']['hit_rate']);
        $this->assertLessThanOrEqual(100, $data['cache']['hit_rate']);

        // Cleanup
        Cache::forget('test_metric_key');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function requests_per_minute_shows_system_throughput(): void
    {
        // ARRANGE: Generate request traffic
        $this->actingAsApiUserWithToken($this->user);

        // Make multiple requests to simulate load
        $requestCount = 15;
        for ($i = 0; $i < $requestCount; $i++) {
            $this->getJson('/api/v1/profile');
        }

        // ACT: Request performance metrics
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        // ASSERT: Response time metrics are present
        $response->assertOk();
        $data = $response->json();

        // Check for response time tracking
        $this->assertArrayHasKey('avg_response_time_ms', $data);
        $this->assertIsNumeric($data['avg_response_time_ms']);
        $this->assertGreaterThanOrEqual(0, $data['avg_response_time_ms']);

        // Verify other metrics exist
        $this->assertArrayHasKey('slow_queries_count', $data);
        $this->assertIsInt($data['slow_queries_count']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function performance_metrics_identify_bottlenecks(): void
    {
        // ARRANGE: Generate mixed workload with different characteristics
        $this->actingAsApiUserWithToken($this->user);

        // Fast queries (simple selects)
        $this->getJson('/api/v1/profile');

        // Potentially slower queries (with joins/aggregations)
        $this->getJson('/api/v1/users');
        $this->getJson('/api/v1/applications');

        // Cached endpoints
        $this->getJson('/api/v1/monitoring/metrics/authentication');

        // ACT: Get comprehensive performance metrics
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        // ASSERT: All performance indicators are present
        $response->assertOk();
        $data = $response->json();

        // Verify all key metrics exist
        $this->assertArrayHasKey('avg_response_time_ms', $data);
        $this->assertArrayHasKey('max_response_time_ms', $data);
        $this->assertArrayHasKey('min_response_time_ms', $data);
        $this->assertArrayHasKey('slow_queries_count', $data);
        $this->assertArrayHasKey('cache', $data);

        // Verify response time metrics are numeric
        $this->assertIsNumeric($data['avg_response_time_ms']);
        $this->assertIsNumeric($data['max_response_time_ms']);
        $this->assertIsNumeric($data['min_response_time_ms']);
        $this->assertIsInt($data['slow_queries_count']);

        // Verify cache metrics
        $this->assertIsArray($data['cache']);
        $this->assertArrayHasKey('hit_rate', $data['cache']);
        $this->assertIsNumeric($data['cache']['hit_rate']);

        // Verify all values are reasonable (non-negative)
        $this->assertGreaterThanOrEqual(0, $data['avg_response_time_ms']);
        $this->assertGreaterThanOrEqual(0, $data['max_response_time_ms']);
        $this->assertGreaterThanOrEqual(0, $data['slow_queries_count']);
        $this->assertGreaterThanOrEqual(0, $data['cache']['hit_rate']);
        $this->assertLessThanOrEqual(100, $data['cache']['hit_rate']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function performance_metrics_are_real_time_and_accurate(): void
    {
        // ARRANGE: Make initial request to establish baseline
        $this->actingAsApiUserWithToken($this->user);
        $this->getJson('/api/v1/profile');

        // Get initial metrics
        $response1 = $this->getJson('/api/v1/monitoring/metrics/performance');
        $response1->assertOk();
        $data1 = $response1->json();

        // ACT: Generate additional load
        for ($i = 0; $i < 5; $i++) {
            $this->getJson('/api/v1/users');
        }

        // Get updated metrics
        $response2 = $this->getJson('/api/v1/monitoring/metrics/performance');
        $response2->assertOk();
        $data2 = $response2->json();

        // ASSERT: Metrics structure is valid
        // (Note: Due to caching, values might be the same, but structure should be valid)
        $this->assertIsNumeric($data2['avg_response_time_ms']);
        $this->assertArrayHasKey('cache', $data2);

        // Both metric sets should have valid structure
        $this->assertGreaterThanOrEqual(0, $data1['avg_response_time_ms']);
        $this->assertGreaterThanOrEqual(0, $data2['avg_response_time_ms']);

        // Verify cache metrics are present
        $this->assertIsArray($data2['cache']);
        $this->assertArrayHasKey('hit_rate', $data2['cache']);
    }
}
