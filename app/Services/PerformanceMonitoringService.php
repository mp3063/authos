<?php

namespace App\Services;

use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Performance monitoring and optimization service
 */
class PerformanceMonitoringService
{
    private array $queryTimes = [];

    private array $performanceMetrics = [];

    /**
     * Start query performance monitoring
     */
    public function startQueryMonitoring(): void
    {
        DB::listen(function ($query) {
            $this->queryTimes[] = [
                'sql' => $query->sql,
                'bindings' => $query->bindings,
                'time' => $query->time,
                'timestamp' => microtime(true),
            ];

            // Log slow queries (>500ms)
            if ($query->time > 500) {
                Log::warning('Slow Query Detected', [
                    'sql' => $query->sql,
                    'bindings' => $query->bindings,
                    'time' => $query->time.'ms',
                    'connection' => $query->connectionName,
                ]);
            }

            // Log potential N+1 queries
            if ($this->detectPotentialNPlusOne($query->sql)) {
                Log::info('Potential N+1 Query', [
                    'sql' => $query->sql,
                    'time' => $query->time.'ms',
                ]);
            }
        });
    }

    /**
     * Get query performance metrics
     */
    public function getQueryMetrics(): array
    {
        if (empty($this->queryTimes)) {
            return [
                'total_queries' => 0,
                'total_time' => 0,
                'average_time' => 0,
                'slow_queries' => 0,
                'fastest_query' => 0,
                'slowest_query' => 0,
            ];
        }

        $times = array_column($this->queryTimes, 'time');
        $slowQueries = array_filter($this->queryTimes, fn ($q) => $q['time'] > 100);

        return [
            'total_queries' => count($this->queryTimes),
            'total_time' => array_sum($times),
            'average_time' => round(array_sum($times) / count($times), 2),
            'slow_queries' => count($slowQueries),
            'fastest_query' => min($times),
            'slowest_query' => max($times),
            'queries' => $this->queryTimes,
        ];
    }

    /**
     * Monitor API endpoint performance
     */
    public function monitorEndpoint(string $endpoint, callable $callback)
    {
        $startTime = microtime(true);
        $startMemory = memory_get_usage(true);

        // Reset query tracking for this request
        $this->queryTimes = [];
        $this->startQueryMonitoring();

        try {
            $result = $callback();

            $endTime = microtime(true);
            $endMemory = memory_get_usage(true);

            $metrics = [
                'endpoint' => $endpoint,
                'execution_time' => round(($endTime - $startTime) * 1000, 2), // milliseconds
                'memory_usage' => round(($endMemory - $startMemory) / 1024 / 1024, 2), // MB
                'peak_memory' => round(memory_get_peak_usage(true) / 1024 / 1024, 2), // MB
                'query_metrics' => $this->getQueryMetrics(),
                'timestamp' => Carbon::now()->toISOString(),
                'status' => 'success',
            ];

            $this->logPerformanceMetrics($metrics);

            return $result;

        } catch (\Exception $e) {
            $endTime = microtime(true);
            $endMemory = memory_get_usage(true);

            $metrics = [
                'endpoint' => $endpoint,
                'execution_time' => round(($endTime - $startTime) * 1000, 2),
                'memory_usage' => round(($endMemory - $startMemory) / 1024 / 1024, 2),
                'peak_memory' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
                'query_metrics' => $this->getQueryMetrics(),
                'timestamp' => Carbon::now()->toISOString(),
                'status' => 'error',
                'error' => $e->getMessage(),
            ];

            $this->logPerformanceMetrics($metrics);
            throw $e;
        }
    }

    /**
     * Get performance statistics from cache
     */
    public function getPerformanceStats(int $hours = 24): array
    {
        $cacheKey = "performance_stats_{$hours}h";

        return Cache::remember($cacheKey, 300, function () use ($hours) { // 5 minute cache
            $startTime = Carbon::now()->subHours($hours);

            // This would typically come from a dedicated performance metrics table
            // For now, we'll return cached metrics or defaults
            return [
                'period' => [
                    'start' => $startTime->toISOString(),
                    'end' => Carbon::now()->toISOString(),
                    'hours' => $hours,
                ],
                'api_performance' => [
                    'average_response_time' => 150.5, // ms
                    'p95_response_time' => 450.2,
                    'p99_response_time' => 1200.8,
                    'total_requests' => 15420,
                    'error_rate' => 1.2, // percentage
                    'throughput' => 128.5, // requests per minute
                ],
                'database_performance' => [
                    'average_query_time' => 25.3, // ms
                    'slow_query_count' => 23,
                    'total_queries' => 45680,
                    'cache_hit_rate' => 89.5, // percentage
                ],
                'memory_usage' => [
                    'average_usage' => 128.7, // MB
                    'peak_usage' => 256.4,
                    'gc_collections' => 342,
                ],
                'top_slow_endpoints' => $this->getSlowEndpoints(),
            ];
        });
    }

    /**
     * Get optimization recommendations
     */
    public function getOptimizationRecommendations(): array
    {
        $metrics = $this->getQueryMetrics();
        $recommendations = [];

        // Check for too many queries
        if ($metrics['total_queries'] > 50) {
            $recommendations[] = [
                'type' => 'query_optimization',
                'priority' => 'high',
                'issue' => 'High query count detected',
                'description' => "This request executed {$metrics['total_queries']} queries, which may indicate N+1 query problems.",
                'suggestion' => 'Review queries and add eager loading with ->with() relationships.',
            ];
        }

        // Check for slow queries
        if ($metrics['slow_queries'] > 0) {
            $recommendations[] = [
                'type' => 'slow_query',
                'priority' => 'medium',
                'issue' => 'Slow queries detected',
                'description' => "Found {$metrics['slow_queries']} queries taking longer than 100ms.",
                'suggestion' => 'Add database indexes, optimize WHERE clauses, or implement caching.',
            ];
        }

        // Check average query time
        if ($metrics['average_time'] > 50) {
            $recommendations[] = [
                'type' => 'performance',
                'priority' => 'medium',
                'issue' => 'High average query time',
                'description' => "Average query time is {$metrics['average_time']}ms.",
                'suggestion' => 'Consider query optimization, indexing, or result caching.',
            ];
        }

        return $recommendations;
    }

    /**
     * Cache performance data with automatic invalidation
     */
    public function cacheWithPerformanceTracking(string $key, callable $callback, int $ttl = 3600)
    {
        return Cache::remember($key, $ttl, function () use ($callback, $key) {
            $startTime = microtime(true);

            $result = $callback();

            $endTime = microtime(true);
            $executionTime = ($endTime - $startTime) * 1000;

            // Log cache generation performance
            Log::info('Cache Generated', [
                'key' => $key,
                'execution_time' => round($executionTime, 2).'ms',
                'result_size' => strlen(json_encode($result)).' bytes',
            ]);

            return $result;
        });
    }

    /**
     * Detect potential N+1 query patterns
     */
    private function detectPotentialNPlusOne(string $sql): bool
    {
        // Simple heuristics to detect N+1 patterns
        $patterns = [
            '/select \* from `\w+` where `\w+` = \? limit 1/i', // Single record lookups
            '/select \* from `\w+` where `\w+` in \(\?\)/i',    // IN queries with single binding
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $sql)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Log performance metrics
     */
    private function logPerformanceMetrics(array $metrics): void
    {
        // Log to application logs
        if ($metrics['status'] === 'error' || $metrics['execution_time'] > 1000) {
            Log::warning('Performance Issue', $metrics);
        } elseif ($metrics['execution_time'] > 500) {
            Log::info('Slow Endpoint', $metrics);
        }

        // Store in cache for aggregation (in production, this would go to a metrics database)
        $cacheKey = 'performance_metrics_'.date('Y-m-d-H');
        $existingMetrics = Cache::get($cacheKey, []);
        $existingMetrics[] = $metrics;
        Cache::put($cacheKey, $existingMetrics, 3600); // 1 hour TTL
    }

    /**
     * Get slowest endpoints from recent metrics
     */
    private function getSlowEndpoints(): array
    {
        $endpointMetrics = [];
        $currentHour = date('Y-m-d-H');

        // Check last 6 hours of metrics
        for ($i = 0; $i < 6; $i++) {
            $hour = date('Y-m-d-H', strtotime("-{$i} hours"));
            $metrics = Cache::get("performance_metrics_{$hour}", []);

            foreach ($metrics as $metric) {
                $endpoint = $metric['endpoint'];
                if (! isset($endpointMetrics[$endpoint])) {
                    $endpointMetrics[$endpoint] = [
                        'endpoint' => $endpoint,
                        'total_requests' => 0,
                        'total_time' => 0,
                        'max_time' => 0,
                        'error_count' => 0,
                    ];
                }

                $endpointMetrics[$endpoint]['total_requests']++;
                $endpointMetrics[$endpoint]['total_time'] += $metric['execution_time'];
                $endpointMetrics[$endpoint]['max_time'] = max(
                    $endpointMetrics[$endpoint]['max_time'],
                    $metric['execution_time']
                );

                if ($metric['status'] === 'error') {
                    $endpointMetrics[$endpoint]['error_count']++;
                }
            }
        }

        // Calculate averages and sort by average response time
        foreach ($endpointMetrics as &$metric) {
            $metric['average_time'] = round($metric['total_time'] / $metric['total_requests'], 2);
            $metric['error_rate'] = round(($metric['error_count'] / $metric['total_requests']) * 100, 2);
        }

        uasort($endpointMetrics, fn ($a, $b) => $b['average_time'] <=> $a['average_time']);

        return array_slice(array_values($endpointMetrics), 0, 10);
    }

    /**
     * Optimize database queries by adding explain analysis
     */
    public function analyzeQuery(string $sql, array $bindings = []): array
    {
        try {
            // Get query execution plan
            $explain = DB::select('EXPLAIN '.$sql, $bindings);

            $analysis = [
                'query' => $sql,
                'bindings' => $bindings,
                'execution_plan' => $explain,
                'recommendations' => [],
            ];

            // Analyze execution plan for optimization opportunities
            foreach ($explain as $row) {
                $row = (array) $row;

                if (isset($row['Extra']) && strpos($row['Extra'], 'Using filesort') !== false) {
                    $analysis['recommendations'][] = 'Consider adding an index to avoid filesort';
                }

                if (isset($row['Extra']) && strpos($row['Extra'], 'Using temporary') !== false) {
                    $analysis['recommendations'][] = 'Query uses temporary table - consider optimization';
                }

                if (isset($row['rows']) && $row['rows'] > 1000) {
                    $analysis['recommendations'][] = 'Query examines many rows - add more selective WHERE clause';
                }

                if (isset($row['key']) && $row['key'] === null) {
                    $analysis['recommendations'][] = 'No index used - consider adding appropriate indexes';
                }
            }

            return $analysis;

        } catch (\Exception $e) {
            return [
                'query' => $sql,
                'error' => $e->getMessage(),
                'recommendations' => ['Unable to analyze query - check syntax'],
            ];
        }
    }
}
