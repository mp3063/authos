<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class PerformanceBenchmarkService
{
    private array $results = [];

    private float $startTime;

    private int $startMemory;

    /**
     * Start a benchmark test.
     */
    public function start(string $name): void
    {
        $this->startTime = microtime(true);
        $this->startMemory = memory_get_usage(true);

        Log::debug("Benchmark started: {$name}");
    }

    /**
     * Stop a benchmark test and record results.
     */
    public function stop(string $name, array $metadata = []): array
    {
        $endTime = microtime(true);
        $endMemory = memory_get_usage(true);

        $result = [
            'name' => $name,
            'duration_ms' => round(($endTime - $this->startTime) * 1000, 2),
            'memory_mb' => round(($endMemory - $this->startMemory) / 1024 / 1024, 2),
            'peak_memory_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'timestamp' => now()->toIso8601String(),
            'metadata' => $metadata,
        ];

        $this->results[] = $result;

        Log::debug("Benchmark completed: {$name}", $result);

        return $result;
    }

    /**
     * Run a benchmark for a callable function.
     */
    public function benchmark(string $name, callable $function, array $metadata = []): array
    {
        $this->start($name);

        try {
            $result = $function();
            $metadata['success'] = true;
            $metadata['result'] = is_scalar($result) ? $result : gettype($result);
        } catch (\Exception $e) {
            $metadata['success'] = false;
            $metadata['error'] = $e->getMessage();
        }

        return $this->stop($name, $metadata);
    }

    /**
     * Benchmark a database query.
     */
    public function benchmarkQuery(string $name, string $query, array $bindings = []): array
    {
        DB::enableQueryLog();

        $this->start($name);

        try {
            $result = DB::select($query, $bindings);
            $queryLog = DB::getQueryLog();

            $metadata = [
                'success' => true,
                'rows' => count($result),
                'queries' => count($queryLog),
                'query_time_ms' => collect($queryLog)->sum('time'),
            ];
        } catch (\Exception $e) {
            $metadata = [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        } finally {
            DB::disableQueryLog();
        }

        return $this->stop($name, $metadata);
    }

    /**
     * Benchmark an HTTP endpoint.
     */
    public function benchmarkEndpoint(string $name, string $url, string $method = 'GET', array $options = []): array
    {
        $this->start($name);

        try {
            $response = match (strtoupper($method)) {
                'GET' => Http::get($url, $options),
                'POST' => Http::post($url, $options),
                'PUT' => Http::put($url, $options),
                'DELETE' => Http::delete($url, $options),
                default => throw new \InvalidArgumentException("Unsupported HTTP method: {$method}"),
            };

            $metadata = [
                'success' => $response->successful(),
                'status' => $response->status(),
                'response_size_kb' => round(strlen($response->body()) / 1024, 2),
                'url' => $url,
                'method' => $method,
            ];
        } catch (\Exception $e) {
            $metadata = [
                'success' => false,
                'error' => $e->getMessage(),
                'url' => $url,
                'method' => $method,
            ];
        }

        return $this->stop($name, $metadata);
    }

    /**
     * Run multiple iterations of a benchmark and calculate statistics.
     */
    public function benchmarkIterations(string $name, callable $function, int $iterations = 100): array
    {
        $results = [];

        for ($i = 0; $i < $iterations; $i++) {
            $result = $this->benchmark("{$name}_iteration_{$i}", $function);
            $results[] = $result['duration_ms'];
        }

        $stats = [
            'name' => $name,
            'iterations' => $iterations,
            'min_ms' => min($results),
            'max_ms' => max($results),
            'avg_ms' => round(array_sum($results) / count($results), 2),
            'median_ms' => $this->calculateMedian($results),
            'p95_ms' => $this->calculatePercentile($results, 95),
            'p99_ms' => $this->calculatePercentile($results, 99),
        ];

        Log::info("Benchmark iterations completed: {$name}", $stats);

        return $stats;
    }

    /**
     * Get all benchmark results.
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Get summary statistics from all benchmarks.
     */
    public function getSummary(): array
    {
        if (empty($this->results)) {
            return [];
        }

        $durations = array_column($this->results, 'duration_ms');
        $memories = array_column($this->results, 'memory_mb');

        return [
            'total_benchmarks' => count($this->results),
            'total_duration_ms' => round(array_sum($durations), 2),
            'avg_duration_ms' => round(array_sum($durations) / count($durations), 2),
            'max_duration_ms' => max($durations),
            'min_duration_ms' => min($durations),
            'total_memory_mb' => round(array_sum($memories), 2),
            'avg_memory_mb' => round(array_sum($memories) / count($memories), 2),
            'max_memory_mb' => max($memories),
        ];
    }

    /**
     * Reset all benchmark results.
     */
    public function reset(): void
    {
        $this->results = [];
    }

    /**
     * Calculate median value.
     */
    private function calculateMedian(array $values): float
    {
        sort($values);
        $count = count($values);
        $middle = floor($count / 2);

        if ($count % 2 == 0) {
            return round(($values[$middle - 1] + $values[$middle]) / 2, 2);
        }

        return round($values[$middle], 2);
    }

    /**
     * Calculate percentile value.
     */
    private function calculatePercentile(array $values, int $percentile): float
    {
        sort($values);
        $index = ceil((count($values) * $percentile) / 100) - 1;

        return round($values[$index] ?? 0, 2);
    }

    /**
     * Export results to array format.
     */
    public function export(): array
    {
        return [
            'summary' => $this->getSummary(),
            'results' => $this->results,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
