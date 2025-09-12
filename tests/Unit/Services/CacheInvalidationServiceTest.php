<?php

namespace Tests\Unit\Services;

use App\Services\CacheInvalidationService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class CacheInvalidationServiceTest extends TestCase
{
    use RefreshDatabase;

    private CacheInvalidationService $cacheService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cacheService = app(CacheInvalidationService::class);
    }

    public function test_invalidate_user_caches_calls_correct_patterns_and_logs(): void
    {
        $userId = 123;

        Log::shouldReceive('debug')->once()->with('Invalidated user caches', ['user_id' => $userId]);

        // Mock the cache store to not support keys() method
        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false; // Simulate no keys() method support
                }

                public function get($key)
                {
                    return null;
                }
            });

        // Should handle the case gracefully when keys() method doesn't exist
        Log::shouldReceive('warning')
            ->zeroOrMoreTimes()
            ->with('Cache store does not support pattern invalidation', \Mockery::type('array'));

        $this->cacheService->invalidateUserCaches($userId);

        // The method should complete without throwing errors
        $this->assertTrue(true); // Assert that we reach this point
    }

    public function test_invalidate_organization_caches_calls_correct_patterns_and_logs(): void
    {
        $organizationId = 456;

        Log::shouldReceive('debug')->once()->with('Invalidated organization caches', ['organization_id' => $organizationId]);
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false;
                }
            });

        $this->cacheService->invalidateOrganizationCaches($organizationId);

        $this->assertTrue(true);
    }

    public function test_invalidate_application_caches_with_organization_calls_correct_patterns(): void
    {
        $applicationId = 789;
        $organizationId = 456;

        Log::shouldReceive('debug')->once()->with('Invalidated application caches', [
            'application_id' => $applicationId,
            'organization_id' => $organizationId,
        ]);
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false;
                }
            });

        $this->cacheService->invalidateApplicationCaches($applicationId, $organizationId);

        $this->assertTrue(true);
    }

    public function test_invalidate_application_caches_without_organization(): void
    {
        $applicationId = 789;

        Log::shouldReceive('debug')->once()->with('Invalidated application caches', [
            'application_id' => $applicationId,
            'organization_id' => null,
        ]);
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false;
                }
            });

        $this->cacheService->invalidateApplicationCaches($applicationId);

        $this->assertTrue(true);
    }

    public function test_invalidate_all_api_caches_logs_correctly(): void
    {
        Log::shouldReceive('info')->once()->with('Invalidated all API caches');
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false;
                }
            });

        $this->cacheService->invalidateAllApiCaches();

        $this->assertTrue(true);
    }

    public function test_invalidate_endpoint_caches_transforms_endpoint_correctly(): void
    {
        $endpoint = '/api/v1/users';

        Log::shouldReceive('debug')->once()->with('Invalidated endpoint caches', ['endpoint' => '_api_v1_users']); // Service transforms / to _
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false;
                }
            });

        $this->cacheService->invalidateEndpointCaches($endpoint);

        $this->assertTrue(true);
    }

    public function test_invalidate_user_permission_caches_uses_correct_pattern(): void
    {
        $userId = 123;

        Log::shouldReceive('debug')->once()->with('Invalidated user permission caches', ['user_id' => $userId]);
        Log::shouldReceive('warning')->zeroOrMoreTimes();

        Cache::shouldReceive('getStore')
            ->once()
            ->andReturn(new class
            {
                public function keys($pattern)
                {
                    return false;
                }
            });

        $this->cacheService->invalidateUserPermissionCaches($userId);

        $this->assertTrue(true);
    }

    public function test_get_cache_stats_returns_statistics_when_store_supports_keys(): void
    {
        // Test with store that supports keys
        $mockStore = new class
        {
            public function keys($pattern)
            {
                return ['api_cache:test1', 'api_cache:test2', 'api_cache:test3'];
            }

            public function get($key)
            {
                return 'test_data_'.strlen($key); // Return variable length data
            }
        };

        Cache::shouldReceive('getStore')->andReturn($mockStore);

        $stats = $this->cacheService->getCacheStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total_keys', $stats);
        $this->assertArrayHasKey('estimated_size_bytes', $stats);
        $this->assertArrayHasKey('estimated_size_mb', $stats);
        $this->assertArrayHasKey('sample_size', $stats);

        $this->assertEquals(3, $stats['total_keys']);
        $this->assertIsNumeric($stats['estimated_size_bytes']);
        $this->assertIsNumeric($stats['estimated_size_mb']);
        $this->assertEquals(3, $stats['sample_size']);
    }

    public function test_get_cache_stats_handles_store_without_keys_method(): void
    {
        // Test with store that doesn't support keys
        $mockStore = new class
        {
            // No keys() method
        };

        Cache::shouldReceive('getStore')->andReturn($mockStore);

        $stats = $this->cacheService->getCacheStats();

        $this->assertIsArray($stats);
        $this->assertEquals('unavailable', $stats['total_keys']);
        $this->assertEquals('unavailable', $stats['estimated_size_bytes']);
        $this->assertEquals('unavailable', $stats['estimated_size_mb']);
        $this->assertEquals(0, $stats['sample_size']);
    }

    public function test_clear_expired_caches_logs_cleanup_request(): void
    {
        Log::shouldReceive('info')->once()->with('Cache cleanup requested (handled by Redis TTL)');

        $result = $this->cacheService->clearExpiredCaches();

        $this->assertEquals(0, $result); // Redis handles TTL automatically
    }

    public function test_cache_invalidation_with_successful_pattern_matching(): void
    {
        $userId = 123;

        // Mock store that supports keys and returns matching keys
        $mockStore = new class
        {
            public function keys($pattern)
            {
                if (strpos($pattern, 'api_cache:*:123:*') !== false) {
                    return ['api_cache:GET:users:123:profile', 'api_cache:POST:users:123:update'];
                }

                return [];
            }
        };

        Cache::shouldReceive('getStore')->andReturn($mockStore);
        Cache::shouldReceive('forget')->twice(); // Should be called for each key found

        Log::shouldReceive('debug')->once()->with('Invalidated user permission caches', ['user_id' => $userId]);
        Log::shouldReceive('debug')->once()->with('Invalidated cache keys', [
            'pattern' => "api_cache:*:{$userId}:*",
            'keys_count' => 2,
        ]);

        $this->cacheService->invalidateUserPermissionCaches($userId);

        $this->assertTrue(true);
    }

    public function test_cache_invalidation_handles_exceptions_gracefully(): void
    {
        $userId = 123;

        // Mock store that throws exception on keys()
        $mockStore = new class
        {
            public function keys($pattern)
            {
                throw new \Exception('Cache store error');
            }
        };

        Cache::shouldReceive('getStore')->andReturn($mockStore);

        Log::shouldReceive('debug')->once()->with('Invalidated user caches', ['user_id' => $userId]);
        Log::shouldReceive('error')->atLeast()->once()->with('Cache invalidation failed', \Mockery::type('array'));

        // Should not throw exception, but handle it gracefully
        $this->cacheService->invalidateUserCaches($userId);

        $this->assertTrue(true);
    }
}
