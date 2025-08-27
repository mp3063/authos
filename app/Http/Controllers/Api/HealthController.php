<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use Laravel\Passport\Token;

class HealthController extends Controller
{
    /**
     * Basic health check endpoint.
     */
    public function index(): JsonResponse
    {
        return response()->json([
            'status' => 'healthy',
            'timestamp' => now()->toISOString(),
            'version' => config('app.version', '1.0.0'),
            'environment' => config('app.env'),
        ]);
    }

    /**
     * Detailed health check with dependencies.
     */
    public function detailed(): JsonResponse
    {
        $checks = [
            'database' => $this->checkDatabase(),
            'redis' => $this->checkRedis(),
            'cache' => $this->checkCache(),
            'oauth' => $this->checkOAuth(),
            'storage' => $this->checkStorage(),
        ];

        $overallHealthy = collect($checks)->every(function ($check) {
            return $check['healthy'];
        });

        $responseCode = $overallHealthy ? 200 : 503;

        return response()->json([
            'status' => $overallHealthy ? 'healthy' : 'unhealthy',
            'timestamp' => now()->toISOString(),
            'version' => config('app.version', '1.0.0'),
            'environment' => config('app.env'),
            'uptime' => $this->getUptime(),
            'checks' => $checks,
        ], $responseCode);
    }

    /**
     * Get system metrics.
     */
    public function metrics(): JsonResponse
    {
        $this->authorize('system.metrics.read');

        $metrics = [
            'system' => $this->getSystemMetrics(),
            'database' => $this->getDatabaseMetrics(),
            'cache' => $this->getCacheMetrics(),
            'oauth' => $this->getOAuthMetrics(),
            'api' => $this->getApiMetrics(),
        ];

        return response()->json([
            'data' => $metrics,
            'timestamp' => now()->toISOString(),
        ]);
    }

    /**
     * Get real-time API metrics.
     */
    public function apiMetrics(): JsonResponse
    {
        $this->authorize('system.metrics.read');

        $date = now()->format('Y-m-d');
        $hour = now()->format('H');
        $minute = now()->format('i');
        $minuteBlock = floor((int)$minute / 5) * 5;

        // Get current 5-minute metrics
        $realtimeKey = 'api_metrics:' . $date . ':realtime:' . $hour . ':' . str_pad($minuteBlock, 2, '0', STR_PAD_LEFT);
        $currentMetrics = Cache::get($realtimeKey, []);

        // Get hourly metrics
        $hourlyKey = 'api_metrics:' . $date . ':hourly:' . $hour;
        $hourlyMetrics = Cache::get($hourlyKey, []);

        // Get daily metrics
        $dailyKey = 'api_metrics:' . $date . ':daily';
        $dailyMetrics = Cache::get($dailyKey, []);

        return response()->json([
            'data' => [
                'current_period' => [
                    'period' => '5min',
                    'start_time' => now()->setMinute($minuteBlock)->setSecond(0)->toISOString(),
                    'metrics' => $this->formatApiMetrics($currentMetrics),
                ],
                'hourly' => [
                    'period' => 'hour',
                    'start_time' => now()->setMinute(0)->setSecond(0)->toISOString(),
                    'metrics' => $this->formatApiMetrics($hourlyMetrics),
                ],
                'daily' => [
                    'period' => 'day',
                    'start_time' => now()->startOfDay()->toISOString(),
                    'metrics' => $this->formatApiMetrics($dailyMetrics),
                ],
            ],
            'timestamp' => now()->toISOString(),
        ]);
    }

    /**
     * Check database connection.
     */
    private function checkDatabase(): array
    {
        try {
            $start = microtime(true);
            DB::select('SELECT 1');
            $responseTime = round((microtime(true) - $start) * 1000, 2);

            return [
                'healthy' => true,
                'response_time_ms' => $responseTime,
                'message' => 'Database connection successful',
            ];
        } catch (\Exception $e) {
            return [
                'healthy' => false,
                'message' => 'Database connection failed: ' . $e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check Redis connection.
     */
    private function checkRedis(): array
    {
        try {
            $start = microtime(true);
            $redis = Redis::connection();
            $redis->ping();
            $responseTime = round((microtime(true) - $start) * 1000, 2);

            return [
                'healthy' => true,
                'response_time_ms' => $responseTime,
                'message' => 'Redis connection successful',
            ];
        } catch (\Exception $e) {
            return [
                'healthy' => false,
                'message' => 'Redis connection failed: ' . $e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check cache functionality.
     */
    private function checkCache(): array
    {
        try {
            $testKey = 'health_check_' . time();
            $testValue = 'test_value_' . uniqid();

            $start = microtime(true);
            Cache::put($testKey, $testValue, 10);
            $cached = Cache::get($testKey);
            Cache::forget($testKey);
            $responseTime = round((microtime(true) - $start) * 1000, 2);

            if ($cached === $testValue) {
                return [
                    'healthy' => true,
                    'response_time_ms' => $responseTime,
                    'message' => 'Cache read/write successful',
                ];
            } else {
                return [
                    'healthy' => false,
                    'message' => 'Cache read/write verification failed',
                ];
            }
        } catch (\Exception $e) {
            return [
                'healthy' => false,
                'message' => 'Cache operation failed: ' . $e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check OAuth/Passport functionality.
     */
    private function checkOAuth(): array
    {
        try {
            $start = microtime(true);
            
            // Check if we can query tokens table
            $activeTokensCount = Token::where('expires_at', '>', now())->count();
            
            $responseTime = round((microtime(true) - $start) * 1000, 2);

            return [
                'healthy' => true,
                'response_time_ms' => $responseTime,
                'message' => 'OAuth system operational',
                'active_tokens' => $activeTokensCount,
            ];
        } catch (\Exception $e) {
            return [
                'healthy' => false,
                'message' => 'OAuth system check failed: ' . $e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check storage functionality.
     */
    private function checkStorage(): array
    {
        try {
            $testFile = 'health_check_' . time() . '.txt';
            $testContent = 'Health check test content';

            $start = microtime(true);
            \Storage::disk('local')->put($testFile, $testContent);
            $readContent = \Storage::disk('local')->get($testFile);
            \Storage::disk('local')->delete($testFile);
            $responseTime = round((microtime(true) - $start) * 1000, 2);

            if ($readContent === $testContent) {
                return [
                    'healthy' => true,
                    'response_time_ms' => $responseTime,
                    'message' => 'Storage read/write successful',
                ];
            } else {
                return [
                    'healthy' => false,
                    'message' => 'Storage read/write verification failed',
                ];
            }
        } catch (\Exception $e) {
            return [
                'healthy' => false,
                'message' => 'Storage operation failed: ' . $e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get application uptime.
     */
    private function getUptime(): array
    {
        $uptimeSeconds = Cache::remember('app_uptime_start', 86400, function () {
            return time();
        });

        $currentUptime = time() - $uptimeSeconds;

        return [
            'seconds' => $currentUptime,
            'human' => $this->formatUptime($currentUptime),
            'started_at' => date('Y-m-d H:i:s', $uptimeSeconds),
        ];
    }

    /**
     * Format uptime seconds to human readable format.
     */
    private function formatUptime(int $seconds): string
    {
        $days = floor($seconds / 86400);
        $hours = floor(($seconds % 86400) / 3600);
        $minutes = floor(($seconds % 3600) / 60);
        $secs = $seconds % 60;

        $parts = [];
        if ($days > 0) $parts[] = "{$days}d";
        if ($hours > 0) $parts[] = "{$hours}h";
        if ($minutes > 0) $parts[] = "{$minutes}m";
        if ($secs > 0 || empty($parts)) $parts[] = "{$secs}s";

        return implode(' ', $parts);
    }

    /**
     * Get system metrics.
     */
    private function getSystemMetrics(): array
    {
        return [
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'memory_usage' => [
                'current' => memory_get_usage(true),
                'peak' => memory_get_peak_usage(true),
                'limit' => ini_get('memory_limit'),
            ],
            'cpu_load' => function_exists('sys_getloadavg') ? sys_getloadavg() : null,
        ];
    }

    /**
     * Get database metrics.
     */
    private function getDatabaseMetrics(): array
    {
        try {
            $users = DB::table('users')->count();
            $organizations = DB::table('organizations')->count();
            $applications = DB::table('applications')->count();
            $authLogs = DB::table('authentication_logs')->whereDate('created_at', now())->count();

            return [
                'users_total' => $users,
                'organizations_total' => $organizations,
                'applications_total' => $applications,
                'auth_logs_today' => $authLogs,
            ];
        } catch (\Exception $e) {
            return [
                'error' => 'Failed to retrieve database metrics: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Get cache metrics.
     */
    private function getCacheMetrics(): array
    {
        try {
            $redis = Redis::connection();
            $info = $redis->info();

            return [
                'memory_usage' => $info['used_memory'] ?? null,
                'connected_clients' => $info['connected_clients'] ?? null,
                'keyspace_hits' => $info['keyspace_hits'] ?? null,
                'keyspace_misses' => $info['keyspace_misses'] ?? null,
                'hit_ratio' => isset($info['keyspace_hits'], $info['keyspace_misses']) 
                    ? round(($info['keyspace_hits'] / ($info['keyspace_hits'] + $info['keyspace_misses'])) * 100, 2)
                    : null,
            ];
        } catch (\Exception $e) {
            return [
                'error' => 'Failed to retrieve cache metrics: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Get OAuth metrics.
     */
    private function getOAuthMetrics(): array
    {
        try {
            $activeTokens = Token::where('expires_at', '>', now())->count();
            $totalTokens = Token::count();
            $expiredTokens = Token::where('expires_at', '<=', now())->count();

            return [
                'active_tokens' => $activeTokens,
                'total_tokens' => $totalTokens,
                'expired_tokens' => $expiredTokens,
            ];
        } catch (\Exception $e) {
            return [
                'error' => 'Failed to retrieve OAuth metrics: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Get API metrics from cache.
     */
    private function getApiMetrics(): array
    {
        $date = now()->format('Y-m-d');
        $dailyKey = 'api_metrics:' . $date . ':daily';
        $dailyMetrics = Cache::get($dailyKey, []);

        return $this->formatApiMetrics($dailyMetrics);
    }

    /**
     * Format API metrics for response.
     */
    private function formatApiMetrics(array $metrics): array
    {
        if (empty($metrics)) {
            return [
                'requests' => 0,
                'errors' => 0,
                'error_rate' => 0,
                'avg_response_time' => 0,
                'unique_users' => 0,
            ];
        }

        $totalRequests = $metrics['total_requests'] ?? 0;
        $totalErrors = $metrics['total_errors'] ?? 0;
        $totalExecutionTime = $metrics['total_execution_time'] ?? 0;
        $uniqueUsers = count($metrics['unique_users'] ?? []);

        return [
            'requests' => $totalRequests,
            'errors' => $totalErrors,
            'error_rate' => $totalRequests > 0 ? round(($totalErrors / $totalRequests) * 100, 2) : 0,
            'avg_response_time' => $totalRequests > 0 ? round($totalExecutionTime / $totalRequests, 2) : 0,
            'max_response_time' => $metrics['max_execution_time'] ?? 0,
            'min_response_time' => $metrics['min_execution_time'] !== PHP_FLOAT_MAX ? $metrics['min_execution_time'] : 0,
            'unique_users' => $uniqueUsers,
            'top_endpoints' => array_slice($metrics['endpoints'] ?? [], 0, 5, true),
            'status_codes' => $metrics['status_codes'] ?? [],
            'user_agents' => $metrics['user_agents'] ?? [],
        ];
    }
}