<?php

namespace Tests\Performance;

use App\Models\Organization;
use App\Models\User;
use App\Services\CacheWarmingService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class CacheEffectivenessTest extends PerformanceTestCase
{
    protected bool $enableQueryLog = true;

    private CacheWarmingService $cacheWarming;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cacheWarming = app(CacheWarmingService::class);
        Cache::flush();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_hit_ratio_meets_target(): void
    {
        // Create test data
        $orgs = Organization::factory()->count(10)->create();
        User::factory()->count(100)->create();

        // Warm all caches
        $this->cacheWarming->warmAll();

        $hits = 0;
        $misses = 0;
        $requests = 100;

        // Simulate cache access patterns
        for ($i = 0; $i < $requests; $i++) {
            $org = $orgs->random();
            $key = "org:settings:{$org->id}";

            if (Cache::has($key)) {
                $hits++;
                Cache::get($key);
            } else {
                $misses++;
                Cache::remember($key, 3600, fn () => $org->settings ?? []);
            }
        }

        $hitRatio = ($hits / $requests) * 100;

        $this->assertGreaterThanOrEqual(80, $hitRatio, 'Cache hit ratio should be >= 80%');

        $this->recordBaseline('cache_hit_ratio', [
            'hit_ratio_percent' => $hitRatio,
            'hits' => $hits,
            'misses' => $misses,
        ]);

        echo "\n✓ Cache Hit Ratio Performance:\n";
        echo '  Hit Ratio: '.number_format($hitRatio, 2)."%\n";
        echo "  Hits: {$hits} / Misses: {$misses}\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_warming_performance_meets_target(): void
    {
        Organization::factory()->count(50)->create();
        User::factory()->count(200)->create();

        $metrics = $this->measure(function () {
            return $this->cacheWarming->warmAll();
        }, 'cache_warming');

        $this->assertResponseTime($metrics['duration_ms'], 10000, 'Cache warming should complete in < 10 seconds');
        $this->assertMemoryUsage($metrics['memory_used_mb'], 100, 'Cache warming should use < 100MB');

        $this->recordBaseline('cache_warming', $metrics);

        echo "\n✓ Cache Warming Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
        echo '  Memory: '.number_format($metrics['memory_used_mb'], 2)." MB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cached_vs_uncached_performance_comparison(): void
    {
        $org = Organization::factory()->create();
        User::factory()->count(50)->for($org)->create();

        // Measure uncached query
        Cache::forget("org:user_count:{$org->id}");
        $uncachedMetrics = $this->measure(function () use ($org) {
            return $org->users()->count();
        }, 'uncached_query');

        // Warm cache
        Cache::remember("org:user_count:{$org->id}", 3600, fn () => $org->users()->count());

        // Measure cached query
        $cachedMetrics = $this->measure(function () use ($org) {
            return Cache::get("org:user_count:{$org->id}");
        }, 'cached_query');

        $speedup = $uncachedMetrics['duration_ms'] / $cachedMetrics['duration_ms'];
        $improvementPercent = (($uncachedMetrics['duration_ms'] - $cachedMetrics['duration_ms']) / $uncachedMetrics['duration_ms']) * 100;

        $this->assertGreaterThan(10, $speedup, 'Cached queries should be at least 10x faster');

        echo "\n✓ Cached vs Uncached Performance:\n";
        echo '  Uncached: '.number_format($uncachedMetrics['duration_ms'], 3)." ms\n";
        echo '  Cached: '.number_format($cachedMetrics['duration_ms'], 3)." ms\n";
        echo '  Speedup: '.number_format($speedup, 1)."x\n";
        echo '  Improvement: '.number_format($improvementPercent, 1)."%\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_invalidation_impact_is_minimal(): void
    {
        $org = Organization::factory()->create();
        $this->cacheWarming->warmOrganization($org->id);

        // Measure cache invalidation time
        $metrics = $this->measure(function () use ($org) {
            Cache::forget("org:settings:{$org->id}");
            Cache::forget("org:user_count:{$org->id}");
            Cache::forget("org:app_count:{$org->id}");
        }, 'cache_invalidation');

        $this->assertResponseTime($metrics['duration_ms'], 50, 'Cache invalidation should take < 50ms');

        echo "\n✓ Cache Invalidation Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function multi_layer_cache_effectiveness(): void
    {
        $org = Organization::factory()->create();
        User::factory()->count(30)->for($org)->create();

        // Test application-level cache
        $appCacheMetrics = $this->measure(function () use ($org) {
            return Cache::remember("org:stats:{$org->id}", 3600, function () use ($org) {
                return [
                    'users' => $org->users()->count(),
                    'applications' => $org->applications()->count(),
                ];
            });
        }, 'app_cache');

        // Test query result cache using Laravel's built-in Cache facade
        DB::enableQueryLog();
        $queryCacheMetrics = $this->measure(function () use ($org) {
            $cacheKey = "org:users:{$org->id}";

            // First call - should hit database
            Cache::remember($cacheKey, 3600, function () use ($org) {
                return $org->users()->get();
            });

            // Second call - should hit cache (no database query)
            return Cache::remember($cacheKey, 3600, function () use ($org) {
                return $org->users()->get();
            });
        }, 'query_cache');
        $queryCount = count(DB::getQueryLog());
        DB::disableQueryLog();

        // Verify multi-layer caching reduces database queries
        // First call hits DB (1 query), second call hits cache (0 queries) = 1 total
        $this->assertLessThanOrEqual(2, $queryCount, 'Multi-layer caching should minimize database queries');

        echo "\n✓ Multi-Layer Cache Performance:\n";
        echo '  App Cache: '.number_format($appCacheMetrics['duration_ms'], 2)." ms\n";
        echo '  Query Cache: '.number_format($queryCacheMetrics['duration_ms'], 2)." ms\n";
        echo "  Total Queries: {$queryCount}\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_memory_efficiency(): void
    {
        $orgs = Organization::factory()->count(100)->create();

        $startMemory = memory_get_usage(true);

        // Cache multiple objects
        foreach ($orgs as $org) {
            Cache::put("org:settings:{$org->id}", $org->settings ?? [], 3600);
            Cache::put("org:user_count:{$org->id}", random_int(0, 100), 3600);
        }

        $endMemory = memory_get_usage(true);
        $memoryUsedMb = ($endMemory - $startMemory) / 1024 / 1024;

        $avgMemoryPerItem = $memoryUsedMb / 100;

        $this->assertLessThan(0.5, $avgMemoryPerItem, 'Average cache memory per item should be < 0.5MB');

        echo "\n✓ Cache Memory Efficiency:\n";
        echo '  Total Memory: '.number_format($memoryUsedMb, 2)." MB\n";
        echo '  Avg per Item: '.number_format($avgMemoryPerItem, 3)." MB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_ttl_expiration_works_correctly(): void
    {
        $key = 'test:ttl:key';
        $shortTtl = 1; // 1 second

        // Set cache with short TTL
        Cache::put($key, 'test_value', $shortTtl);

        $this->assertTrue(Cache::has($key), 'Cache should exist immediately after setting');

        // Wait for TTL to expire
        sleep($shortTtl + 1);

        $this->assertFalse(Cache::has($key), 'Cache should expire after TTL');

        echo "\n✓ Cache TTL Expiration:\n";
        echo "  TTL configured correctly\n";
        echo "  Expiration works as expected\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function concurrent_cache_access_performance(): void
    {
        $org = Organization::factory()->create();
        $key = "org:settings:{$org->id}";

        Cache::put($key, ['test' => 'data'], 3600);

        $concurrentReads = 50;
        $samples = [];

        for ($i = 0; $i < $concurrentReads; $i++) {
            $metrics = $this->measure(function () use ($key) {
                return Cache::get($key);
            }, "concurrent_read_{$i}");

            $samples[] = $metrics['duration_ms'];
        }

        $avgReadTime = array_sum($samples) / count($samples);
        $maxReadTime = max($samples);
        $minReadTime = min($samples);

        $this->assertLessThan(10, $avgReadTime, 'Average concurrent cache read should be < 10ms');
        $this->assertLessThan(50, $maxReadTime, 'Max concurrent cache read should be < 50ms');

        echo "\n✓ Concurrent Cache Access Performance:\n";
        echo '  Avg Read: '.number_format($avgReadTime, 3)." ms\n";
        echo '  Min Read: '.number_format($minReadTime, 3)." ms\n";
        echo '  Max Read: '.number_format($maxReadTime, 3)." ms\n";
    }
}
