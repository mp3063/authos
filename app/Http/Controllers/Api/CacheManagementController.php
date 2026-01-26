<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\CacheableResponse;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;

class CacheManagementController extends BaseApiController
{
    use CacheableResponse;

    public function __construct()
    {
        $this->middleware('auth:api');
    }

    /**
     * Get real cache statistics.
     */
    public function stats(): JsonResponse
    {
        $driver = config('cache.default');
        $prefix = config('cache.prefix', '');
        $storeConfig = config("cache.stores.{$driver}", []);

        $memoryBytes = 0;

        $stats = [
            'total_keys' => 0,
            'expired_keys' => 0,
            'active_keys' => 0,
            'memory_usage' => '0B',
            'hit_rate' => '0%',
            'driver' => $driver,
            'prefix' => $prefix,
            'cache_enabled' => $driver !== 'array',
            'store_config' => [
                'driver' => $storeConfig['driver'] ?? $driver,
                'table' => $storeConfig['table'] ?? null,
                'connection' => $storeConfig['connection'] ?? null,
            ],
            'timestamp' => now()->toIso8601String(),
        ];

        // Get real counts from the cache store
        if ($driver === 'database') {
            $table = $storeConfig['table'] ?? 'cache';

            try {
                $now = now()->getTimestamp();

                $stats['total_keys'] = DB::table($table)->count();
                $stats['expired_keys'] = DB::table($table)
                    ->where('expiration', '<=', $now)
                    ->where('expiration', '!=', 0)
                    ->count();
                $stats['active_keys'] = DB::table($table)
                    ->where(function ($query) use ($now) {
                        $query->where('expiration', '>', $now)
                            ->orWhere('expiration', 0);
                    })
                    ->count();

                $memoryBytes = (int) DB::table($table)->sum(DB::raw('LENGTH(value)'));
            } catch (Exception $e) {
                logger()->warning('Failed to query cache table stats: '.$e->getMessage());
            }
        } elseif ($driver === 'redis') {
            try {
                $connection = $storeConfig['connection'] ?? 'cache';
                $redis = Redis::connection($connection);
                $info = $redis->info();

                $stats['total_keys'] = (int) ($info['Keyspace']['db0']['keys'] ?? $info['db0']['keys'] ?? $redis->dbsize());
                $stats['active_keys'] = $stats['total_keys'];

                $memoryBytes = (int) ($info['Memory']['used_memory'] ?? $info['used_memory'] ?? 0);

                $hits = (int) ($info['Stats']['keyspace_hits'] ?? $info['keyspace_hits'] ?? 0);
                $misses = (int) ($info['Stats']['keyspace_misses'] ?? $info['keyspace_misses'] ?? 0);
                $total = $hits + $misses;
                if ($total > 0) {
                    $stats['hit_rate'] = round(($hits / $total) * 100, 1).'%';
                }
            } catch (Exception $e) {
                logger()->warning('Failed to query Redis stats: '.$e->getMessage());
            }
        }

        $stats['memory_usage'] = $this->formatBytes($memoryBytes);

        // Fallback hit_rate from stored metric (if not set by Redis)
        if ($stats['hit_rate'] === '0%') {
            $hitRate = cache()->get('cache_hit_rate', 0);
            $stats['hit_rate'] = $hitRate.'%';
        }

        return $this->successResponse($stats, 'Cache statistics retrieved successfully');
    }

    /**
     * Format bytes into a human-readable string.
     */
    private function formatBytes(int $bytes): string
    {
        if ($bytes >= 1073741824) {
            return round($bytes / 1073741824, 1).'GB';
        }

        if ($bytes >= 1048576) {
            return round($bytes / 1048576, 1).'MB';
        }

        if ($bytes >= 1024) {
            return round($bytes / 1024, 1).'KB';
        }

        return $bytes.'B';
    }

    /**
     * Clear all caches.
     */
    public function clearAll(): JsonResponse
    {
        try {
            cache()->flush();

            return $this->successResponse(null, 'All caches cleared successfully');
        } catch (Exception $e) {
            logger()->error('Failed to clear all caches: '.$e->getMessage());

            return $this->errorResponse(
                'Failed to clear caches: '.$e->getMessage(),
                500
            );
        }
    }

    /**
     * Clear cache entries for the authenticated user.
     */
    public function clearUser(Request $request): JsonResponse
    {
        $user = $this->getAuthenticatedUser();

        if (! $user) {
            return $this->unauthorizedResponse('Authentication required');
        }

        $userId = $user->id;
        $cleared = 0;
        $driver = config('cache.default');

        try {
            // Use the trait's invalidation method
            $this->invalidateUserCache($userId);

            // Targeted key deletion by driver
            if ($driver === 'database') {
                $table = config("cache.stores.{$driver}.table", 'cache');
                $prefix = config('cache.prefix', '');

                $patterns = [
                    $prefix."user_data:{$userId}:%",
                    $prefix."api_cache:%user_id%{$userId}%",
                ];

                foreach ($patterns as $pattern) {
                    $cleared += DB::table($table)
                        ->where('key', 'LIKE', $pattern)
                        ->delete();
                }
            } elseif ($driver === 'redis') {
                $storeConfig = config("cache.stores.{$driver}", []);
                $connection = $storeConfig['connection'] ?? 'cache';
                $prefix = config('cache.prefix', '');

                $redis = Redis::connection($connection);
                $patterns = [
                    $prefix."user_data:{$userId}:*",
                    $prefix."api_cache:*user*{$userId}*",
                ];

                foreach ($patterns as $pattern) {
                    $keys = $redis->keys($pattern);
                    if (! empty($keys)) {
                        $cleared += count($keys);
                        $redis->del(...$keys);
                    }
                }
            }

            return $this->successResponse(
                [
                    'user_id' => $userId,
                    'keys_cleared' => $cleared,
                    'driver' => $driver,
                ],
                'User caches cleared successfully'
            );
        } catch (Exception $e) {
            logger()->error("Failed to clear user cache for user {$userId}: ".$e->getMessage());

            return $this->errorResponse(
                'Failed to clear user caches: '.$e->getMessage(),
                500
            );
        }
    }
}
