<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class CacheInvalidationService
{
    /**
     * Invalidate cache patterns when data changes.
     */
    public function invalidateUserCaches(int $userId): void
    {
        $patterns = [
            "api_cache:GET:_api_users:*:{$userId}:*",
            "api_cache:GET:_api_users_{$userId}:*",
            "api_cache:GET:_api_profile:*:{$userId}:*",
        ];

        $this->invalidateByPatterns($patterns);
        
        Log::debug('Invalidated user caches', ['user_id' => $userId]);
    }

    /**
     * Invalidate organization-related caches.
     */
    public function invalidateOrganizationCaches(int $organizationId): void
    {
        $patterns = [
            "api_cache:GET:_api_organizations:*",
            "api_cache:GET:_api_organizations_{$organizationId}:*",
            "api_cache:GET:_api_organizations_{$organizationId}_*:*",
        ];

        $this->invalidateByPatterns($patterns);
        
        Log::debug('Invalidated organization caches', ['organization_id' => $organizationId]);
    }

    /**
     * Invalidate application-related caches.
     */
    public function invalidateApplicationCaches(int $applicationId, int $organizationId = null): void
    {
        $patterns = [
            "api_cache:GET:_api_applications:*",
            "api_cache:GET:_api_applications_{$applicationId}:*",
            "api_cache:GET:_api_applications_{$applicationId}_*:*",
        ];

        if ($organizationId) {
            $patterns[] = "api_cache:GET:_api_organizations_{$organizationId}_applications:*";
        }

        $this->invalidateByPatterns($patterns);
        
        Log::debug('Invalidated application caches', [
            'application_id' => $applicationId,
            'organization_id' => $organizationId,
        ]);
    }

    /**
     * Invalidate all API caches.
     */
    public function invalidateAllApiCaches(): void
    {
        $pattern = 'api_cache:*';
        $this->invalidateByPatterns([$pattern]);
        
        Log::info('Invalidated all API caches');
    }

    /**
     * Invalidate specific endpoint caches.
     */
    public function invalidateEndpointCaches(string $endpoint): void
    {
        $endpoint = str_replace('/', '_', $endpoint);
        $pattern = "api_cache:GET:{$endpoint}:*";
        
        $this->invalidateByPatterns([$pattern]);
        
        Log::debug('Invalidated endpoint caches', ['endpoint' => $endpoint]);
    }

    /**
     * Invalidate caches for a specific user's permissions.
     */
    public function invalidateUserPermissionCaches(int $userId): void
    {
        // When user permissions change, invalidate all their cached responses
        $patterns = [
            "api_cache:*:{$userId}:*",
        ];

        $this->invalidateByPatterns($patterns);
        
        Log::debug('Invalidated user permission caches', ['user_id' => $userId]);
    }

    /**
     * Get cache statistics.
     */
    public function getCacheStats(): array
    {
        $store = Cache::getStore();
        $prefix = config('cache.prefix') ? config('cache.prefix') . ':' : '';
        
        if (method_exists($store, 'keys')) {
            $keys = $store->keys($prefix . 'api_cache:*');
            $totalKeys = count($keys);
            
            // Sample some keys to estimate total size
            $sampleSize = min(100, $totalKeys);
            $sampleKeys = array_slice($keys, 0, $sampleSize);
            $sampleDataSize = 0;
            
            foreach ($sampleKeys as $key) {
                $value = $store->get($key);
                if ($value) {
                    $sampleDataSize += strlen(serialize($value));
                }
            }
            
            $estimatedTotalSize = $sampleSize > 0 
                ? ($sampleDataSize / $sampleSize) * $totalKeys 
                : 0;
                
            return [
                'total_keys' => $totalKeys,
                'estimated_size_bytes' => round($estimatedTotalSize),
                'estimated_size_mb' => round($estimatedTotalSize / 1024 / 1024, 2),
                'sample_size' => $sampleSize,
            ];
        }

        return [
            'total_keys' => 'unavailable',
            'estimated_size_bytes' => 'unavailable',
            'estimated_size_mb' => 'unavailable',
            'sample_size' => 0,
        ];
    }

    /**
     * Clear expired caches.
     */
    public function clearExpiredCaches(): int
    {
        // This is primarily handled by Redis automatically,
        // but we can implement custom logic if needed
        
        Log::info('Cache cleanup requested (handled by Redis TTL)');
        
        return 0; // Redis handles TTL automatically
    }

    /**
     * Invalidate caches by patterns.
     */
    private function invalidateByPatterns(array $patterns): void
    {
        $store = Cache::getStore();
        $prefix = config('cache.prefix') ? config('cache.prefix') . ':' : '';
        
        foreach ($patterns as $pattern) {
            try {
                if (method_exists($store, 'keys')) {
                    $keys = $store->keys($prefix . $pattern);
                    
                    if (!empty($keys)) {
                        foreach ($keys as $key) {
                            // Remove prefix for Cache::forget()
                            $unprefixedKey = $prefix ? str_replace($prefix, '', $key) : $key;
                            Cache::forget($unprefixedKey);
                        }
                        
                        Log::debug('Invalidated cache keys', [
                            'pattern' => $pattern,
                            'keys_count' => count($keys),
                        ]);
                    }
                } else {
                    // Fallback for cache stores that don't support key patterns
                    Log::warning('Cache store does not support pattern invalidation', [
                        'pattern' => $pattern,
                        'store' => get_class($store),
                    ]);
                }
            } catch (\Exception $e) {
                Log::error('Cache invalidation failed', [
                    'pattern' => $pattern,
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }
}