<?php

namespace Tests\Performance;

use App\Models\Organization;
use App\Models\User;
use App\Services\CacheWarmingService;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class CachePerformanceTest extends TestCase
{
    protected CacheWarmingService $cacheWarming;

    protected function setUp(): void
    {
        parent::setUp();

        // Clear and prepare database for performance tests
        Artisan::call('migrate:fresh', ['--seed' => true, '--env' => 'testing']);

        $this->cacheWarming = app(CacheWarmingService::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_warms_organization_caches_efficiently(): void
    {
        // Create test data
        Organization::factory()->count(10)->create();

        $startTime = microtime(true);
        $startMemory = memory_get_usage(true);

        // Warm caches
        $count = $this->cacheWarming->warmOrganizationCaches();

        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        $duration = ($endTime - $startTime) * 1000; // Convert to ms
        $memoryUsed = ($endMemory - $startMemory) / 1024 / 1024; // Convert to MB

        // Assertions
        $this->assertEquals(10, $count);
        $this->assertLessThan(1000, $duration, 'Warming 10 organizations should take less than 1 second');
        $this->assertLessThan(10, $memoryUsed, 'Memory usage should be less than 10MB');

        // Verify caches are set
        $org = Organization::first();
        $this->assertTrue(Cache::has("org:settings:{$org->id}"));
        $this->assertTrue(Cache::has("org:user_count:{$org->id}"));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_warms_user_cache_efficiently(): void
    {
        $org = Organization::factory()->create();
        // Use TestCase helper to properly create user with role
        $user = $this->createUser([
            'organization_id' => $org->id,
        ], 'Organization Owner');

        $startTime = microtime(true);

        $result = $this->cacheWarming->warmUser($user->id);

        $endTime = microtime(true);
        $duration = ($endTime - $startTime) * 1000;

        $this->assertTrue($result);
        $this->assertLessThan(100, $duration, 'Warming user cache should take less than 100ms');

        // Verify caches
        $this->assertTrue(Cache::has("user:permissions:{$user->id}"));
        $this->assertTrue(Cache::has("user:roles:{$user->id}"));
        $this->assertTrue(Cache::has("user:profile:{$user->id}"));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_warms_all_caches_within_time_limit(): void
    {
        // Create test data
        Organization::factory()->count(5)->create();
        User::factory()->count(10)->create();

        $startTime = microtime(true);

        $results = $this->cacheWarming->warmAll();

        $endTime = microtime(true);
        $duration = ($endTime - $startTime) * 1000;

        $this->assertArrayHasKey('organizations', $results);
        $this->assertArrayHasKey('permissions', $results);
        $this->assertArrayHasKey('applications', $results);
        $this->assertArrayHasKey('statistics', $results);

        $this->assertLessThan(5000, $duration, 'Warming all caches should take less than 5 seconds');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cached_queries_are_faster_than_uncached(): void
    {
        $org = Organization::factory()->create();
        $this->cacheWarming->warmOrganization($org->id);

        // Measure uncached access
        Cache::forget("org:settings:{$org->id}");
        $startUncached = microtime(true);
        $settings = Cache::remember("org:settings:{$org->id}", 60, fn () => $org->settings ?? []);
        $uncachedTime = (microtime(true) - $startUncached) * 1000;

        // Measure cached access
        $startCached = microtime(true);
        $cachedSettings = Cache::get("org:settings:{$org->id}");
        $cachedTime = (microtime(true) - $startCached) * 1000;

        $this->assertLessThan($uncachedTime, $cachedTime, 'Cached access should be faster than uncached');
        $this->assertLessThan(10, $cachedTime, 'Cached access should be very fast (< 10ms)');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_all_warmed_caches(): void
    {
        $org = Organization::factory()->create();
        $this->cacheWarming->warmOrganization($org->id);

        $this->assertTrue(Cache::has("org:settings:{$org->id}"));

        $this->cacheWarming->clearAll();

        $this->assertFalse(Cache::has("org:settings:{$org->id}"));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_warming_handles_large_datasets(): void
    {
        // Create a larger dataset
        Organization::factory()->count(50)->create();

        $startTime = microtime(true);
        $startMemory = memory_get_usage(true);

        $count = $this->cacheWarming->warmOrganizationCaches();

        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        $duration = ($endTime - $startTime) * 1000;
        $memoryUsed = ($endMemory - $startMemory) / 1024 / 1024;

        $this->assertEquals(50, $count);
        $this->assertLessThan(5000, $duration, 'Warming 50 organizations should take less than 5 seconds');
        $this->assertLessThan(50, $memoryUsed, 'Memory usage should be less than 50MB');
    }
}
