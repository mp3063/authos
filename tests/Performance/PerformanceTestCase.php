<?php

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

abstract class PerformanceTestCase extends TestCase
{
    protected array $metrics = [];

    protected bool $enableQueryLog = false;

    protected function setUp(): void
    {
        parent::setUp();

        // Seed roles if they don't exist - child classes need this for authentication
        $this->seedRoles();

        // Disable rate limiting for performance tests by overriding the rate limiters
        RateLimiter::for('api', fn () => \Illuminate\Cache\RateLimiting\Limit::none());
        RateLimiter::for('auth', fn () => \Illuminate\Cache\RateLimiting\Limit::none());
        RateLimiter::for('oauth', fn () => \Illuminate\Cache\RateLimiting\Limit::none());

        $this->metrics = [
            'start_time' => microtime(true),
            'start_memory' => memory_get_usage(true),
            'peak_memory' => 0,
            'queries' => [],
            'duration_ms' => 0,
            'memory_used_mb' => 0,
        ];

        if ($this->enableQueryLog) {
            DB::enableQueryLog();
        }
    }

    /**
     * Seed roles for performance tests
     */
    protected function seedRoles(): void
    {
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'Organization Owner', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'web']);
    }

    protected function tearDown(): void
    {
        if ($this->enableQueryLog) {
            DB::disableQueryLog();
        }

        parent::tearDown();
    }

    /**
     * Start measuring performance for a specific operation
     */
    protected function startMeasuring(string $label = 'operation'): void
    {
        $this->metrics[$label] = [
            'start_time' => microtime(true),
            'start_memory' => memory_get_usage(true),
            'queries_before' => $this->enableQueryLog ? count(DB::getQueryLog()) : 0,
        ];
    }

    /**
     * Stop measuring and record metrics
     */
    protected function stopMeasuring(string $label = 'operation'): array
    {
        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);
        $queriesAfter = $this->enableQueryLog ? count(DB::getQueryLog()) : 0;

        // Ensure measurement was started
        if (! isset($this->metrics[$label])) {
            throw new \RuntimeException("Measurement for '{$label}' was not started. Call startMeasuring() first.");
        }

        $metrics = [
            'duration_ms' => ($endTime - $this->metrics[$label]['start_time']) * 1000,
            'memory_used_mb' => ($endMemory - $this->metrics[$label]['start_memory']) / 1024 / 1024,
            'peak_memory_mb' => memory_get_peak_usage(true) / 1024 / 1024,
            'query_count' => $queriesAfter - ($this->metrics[$label]['queries_before'] ?? 0),
        ];

        $this->metrics[$label.'_result'] = $metrics;

        return $metrics;
    }

    /**
     * Measure the performance of a callback
     */
    protected function measure(callable $callback, string $label = 'operation'): array
    {
        $this->startMeasuring($label);
        $result = $callback();
        $metrics = $this->stopMeasuring($label);

        // Store the response for later assertions
        $this->metrics[$label.'_result']['response'] = $result;

        return $metrics;
    }

    /**
     * Assert response time is within threshold
     */
    protected function assertResponseTime(float $actualMs, float $thresholdMs, string $message = ''): void
    {
        $message = $message ?: "Response time {$actualMs}ms exceeds threshold {$thresholdMs}ms";
        $this->assertLessThan($thresholdMs, $actualMs, $message);
    }

    /**
     * Assert query count is within threshold
     */
    protected function assertQueryCount(int $actual, int $threshold, string $message = ''): void
    {
        $message = $message ?: "Query count {$actual} exceeds threshold {$threshold}";
        $this->assertLessThanOrEqual($threshold, $actual, $message);
    }

    /**
     * Assert memory usage is within threshold
     */
    protected function assertMemoryUsage(float $actualMb, float $thresholdMb, string $message = ''): void
    {
        $message = $message ?: "Memory usage {$actualMb}MB exceeds threshold {$thresholdMb}MB";
        $this->assertLessThan($thresholdMb, $actualMb, $message);
    }

    /**
     * Get all queries executed
     */
    protected function getQueries(): array
    {
        return $this->enableQueryLog ? DB::getQueryLog() : [];
    }

    /**
     * Get query statistics
     */
    protected function getQueryStats(): array
    {
        $queries = $this->getQueries();
        $totalTime = array_sum(array_column($queries, 'time'));

        return [
            'count' => count($queries),
            'total_time_ms' => $totalTime,
            'avg_time_ms' => count($queries) > 0 ? $totalTime / count($queries) : 0,
            'slowest_query' => count($queries) > 0 ? max(array_column($queries, 'time')) : 0,
        ];
    }

    /**
     * Record performance baseline for comparison
     */
    protected function recordBaseline(string $test, array $metrics): void
    {
        $baseline = [
            'test' => $test,
            'timestamp' => now()->toIso8601String(),
            'metrics' => $metrics,
        ];

        $baselineFile = storage_path('app/performance_baselines.json');
        $baselines = file_exists($baselineFile)
            ? json_decode(file_get_contents($baselineFile), true)
            : [];

        $baselines[$test] = $baseline;

        file_put_contents($baselineFile, json_encode($baselines, JSON_PRETTY_PRINT));
    }

    /**
     * Compare against baseline
     */
    protected function compareAgainstBaseline(string $test, array $currentMetrics): ?array
    {
        $baselineFile = storage_path('app/performance_baselines.json');

        if (! file_exists($baselineFile)) {
            return null;
        }

        $baselines = json_decode(file_get_contents($baselineFile), true);

        if (! isset($baselines[$test])) {
            return null;
        }

        $baseline = $baselines[$test]['metrics'];
        $comparison = [];

        foreach ($currentMetrics as $key => $value) {
            if (isset($baseline[$key]) && is_numeric($value) && is_numeric($baseline[$key])) {
                $diff = $value - $baseline[$key];
                $percentChange = $baseline[$key] > 0 ? ($diff / $baseline[$key]) * 100 : 0;

                $comparison[$key] = [
                    'baseline' => $baseline[$key],
                    'current' => $value,
                    'diff' => $diff,
                    'percent_change' => round($percentChange, 2),
                    'improved' => $diff < 0,
                ];
            }
        }

        return $comparison;
    }

    /**
     * Generate performance report
     */
    protected function generateReport(array $results): string
    {
        $report = "\n=== Performance Test Report ===\n\n";

        foreach ($results as $testName => $metrics) {
            $report .= "Test: {$testName}\n";
            $report .= str_repeat('-', 50)."\n";

            foreach ($metrics as $key => $value) {
                if (is_numeric($value)) {
                    $report .= sprintf("  %-25s: %s\n", ucfirst(str_replace('_', ' ', $key)), $this->formatMetric($key, $value));
                }
            }

            $report .= "\n";
        }

        return $report;
    }

    /**
     * Format metric value with appropriate unit
     */
    protected function formatMetric(string $key, float $value): string
    {
        if (str_contains($key, 'time') || str_contains($key, 'duration')) {
            return number_format($value, 2).' ms';
        }

        if (str_contains($key, 'memory')) {
            return number_format($value, 2).' MB';
        }

        if (str_contains($key, 'query') || str_contains($key, 'count')) {
            return number_format($value, 0);
        }

        if (str_contains($key, 'rate') || str_contains($key, 'rps')) {
            return number_format($value, 2).' req/s';
        }

        return number_format($value, 2);
    }

    /**
     * Assert performance targets are met
     */
    protected function assertPerformanceTargets(array $metrics, array $targets): void
    {
        foreach ($targets as $key => $threshold) {
            if (isset($metrics[$key])) {
                $this->assertLessThanOrEqual(
                    $threshold,
                    $metrics[$key],
                    "Performance target failed: {$key} ({$metrics[$key]}) exceeds threshold ({$threshold})"
                );
            }
        }
    }

    /**
     * Get Phase 7 performance targets
     */
    protected function getPhase7Targets(): array
    {
        return [
            'auth_response_time_p95' => 100, // ms
            'user_management_response_time_p95' => 150, // ms
            'oauth_token_generation_p95' => 200, // ms
            'bulk_operations_1000_records' => 5000, // ms
            'cache_hit_ratio_min' => 80, // percent
            'queries_per_request_max' => 10,
            'memory_per_request_max' => 20, // MB
            'compression_ratio_min' => 60, // percent
        ];
    }
}
