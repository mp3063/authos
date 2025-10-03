<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Request;

trait CacheableResponse
{
    /**
     * Cache durations for different types of data (in seconds)
     */
    protected array $cacheDurations = [
        'user_permissions' => 600,     // 10 minutes
        'organization_settings' => 1800, // 30 minutes
        'application_config' => 3600,  // 1 hour
        'analytics_data' => 300,       // 5 minutes
        'user_data' => 300,           // 5 minutes
        'organization_data' => 600,   // 10 minutes
        'application_data' => 1800,   // 30 minutes
    ];

    /**
     * Generate a cache key for the current request
     */
    protected function generateCacheKey(string $prefix = '', array $params = []): string
    {
        $request = Request::instance();
        $baseKey = $prefix ?: $request->path();

        // Include query parameters in cache key
        $queryParams = $request->query();
        ksort($queryParams);

        // Include user context in cache key
        $user = auth('api')->user();
        $userContext = $user ? [
            'user_id' => $user->id,
            'org_id' => $user->organization_id,
        ] : [];

        // Combine all parameters
        $allParams = array_merge($queryParams, $params, $userContext);

        // Create unique cache key
        return 'api_cache:'.$baseKey.':'.md5(serialize($allParams));
    }

    /**
     * Cache a response with automatic key generation
     */
    protected function cacheResponse(string $type, callable $callback, array $params = []): mixed
    {
        $duration = $this->cacheDurations[$type] ?? 300;
        $cacheKey = $this->generateCacheKey($type, $params);

        return Cache::remember($cacheKey, $duration, $callback);
    }

    /**
     * Cache organization-scoped data
     */
    protected function cacheOrganizationData(int $organizationId, string $dataType, callable $callback): mixed
    {
        $duration = $this->cacheDurations['organization_data'] ?? 600;
        $cacheKey = "org_data:{$organizationId}:{$dataType}:".md5(Request::instance()->getQueryString() ?? '');

        return Cache::remember($cacheKey, $duration, $callback);
    }

    /**
     * Cache user-scoped data
     */
    protected function cacheUserData(int $userId, string $dataType, callable $callback): mixed
    {
        $duration = $this->cacheDurations['user_data'] ?? 300;
        $cacheKey = "user_data:{$userId}:{$dataType}:".md5(Request::instance()->getQueryString() ?? '');

        return Cache::remember($cacheKey, $duration, $callback);
    }

    /**
     * Cache analytics data with custom duration
     */
    protected function cacheAnalytics(string $analyticsType, array $params, callable $callback, ?int $duration = null): mixed
    {
        $duration = $duration ?? $this->cacheDurations['analytics_data'];
        $cacheKey = "analytics:{$analyticsType}:".md5(serialize($params));

        return Cache::remember($cacheKey, $duration, $callback);
    }

    /**
     * Invalidate cache by pattern
     */
    protected function invalidateCache(string $pattern): void
    {
        // This would require a more sophisticated cache invalidation system
        // For now, we'll use cache tags if available
        try {
            Cache::flush(); // In production, this should be more targeted
        } catch (Exception $e) {
            // Log error but don't fail the request
            logger()->warning('Failed to invalidate cache: '.$e->getMessage());
        }
    }

    /**
     * Invalidate organization-specific cache
     */
    protected function invalidateOrganizationCache(int $organizationId): void
    {
        // Remove organization-specific cache entries
        $patterns = [
            "org_data:{$organizationId}:*",
            "org_analytics_{$organizationId}_*",
            "org_user_metrics_{$organizationId}_*",
            "org_app_metrics_{$organizationId}_*",
            "org_security_metrics_{$organizationId}_*",
        ];

        foreach ($patterns as $pattern) {
            try {
                // In a real implementation, you'd use cache tags or a more sophisticated pattern matching
                Cache::forget($pattern);
            } catch (Exception $e) {
                logger()->warning("Failed to invalidate cache pattern {$pattern}: ".$e->getMessage());
            }
        }
    }

    /**
     * Invalidate user-specific cache
     */
    protected function invalidateUserCache(int $userId): void
    {
        $patterns = [
            "user_data:{$userId}:*",
            "api_cache:*user_id*{$userId}*",
        ];

        foreach ($patterns as $pattern) {
            try {
                Cache::forget($pattern);
            } catch (Exception $e) {
                logger()->warning("Failed to invalidate user cache pattern {$pattern}: ".$e->getMessage());
            }
        }
    }

    /**
     * Get cache statistics for monitoring
     */
    protected function getCacheStats(): array
    {
        return [
            'cache_enabled' => config('cache.default') !== 'array',
            'cache_driver' => config('cache.default'),
            'estimated_keys' => 'N/A', // Would need Redis/Memcached connection to get actual stats
            'hit_rate' => cache()->get('cache_hit_rate', 0),
        ];
    }

    /**
     * Warm up cache for commonly accessed data
     */
    protected function warmupCache(int $organizationId): void
    {
        // Warm up commonly accessed organization data
        $this->cacheOrganizationData($organizationId, 'settings', function () use ($organizationId) {
            return Organization::find($organizationId)?->settings ?? [];
        });

        $this->cacheOrganizationData($organizationId, 'user_count', function () use ($organizationId) {
            return User::where('organization_id', $organizationId)->count();
        });
    }
}
