<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\PerformanceBenchmarkService;
use Illuminate\Console\Command;

class BenchmarkPerformanceCommand extends Command
{
    protected $signature = 'performance:benchmark
                          {--iterations=100 : Number of iterations for each benchmark}
                          {--export= : Export results to file}';

    protected $description = 'Run performance benchmarks on critical operations';

    public function handle(PerformanceBenchmarkService $benchmark): int
    {
        $this->info('Starting performance benchmarks...');
        $iterations = (int) $this->option('iterations');

        $this->newLine();
        $this->info('=== Database Query Benchmarks ===');

        // Benchmark: Simple user query
        $this->info('Benchmarking: User query without relationships...');
        $userStats = $benchmark->benchmarkIterations(
            'user_query_simple',
            fn () => User::first(),
            $iterations
        );
        $this->displayStats($userStats);

        // Benchmark: User query with relationships
        $this->info('Benchmarking: User query with eager loading...');
        $userWithRelStats = $benchmark->benchmarkIterations(
            'user_query_with_relations',
            fn () => User::with(['organization', 'roles', 'applications'])->first(),
            $iterations
        );
        $this->displayStats($userWithRelStats);

        // Benchmark: Organization query
        $this->info('Benchmarking: Organization query...');
        $orgStats = $benchmark->benchmarkIterations(
            'organization_query',
            fn () => Organization::with(['organizationUsers', 'applications'])->first(),
            $iterations
        );
        $this->displayStats($orgStats);

        // Benchmark: Authentication logs with pagination
        $this->info('Benchmarking: Authentication logs pagination...');
        $authLogStats = $benchmark->benchmarkIterations(
            'auth_logs_paginated',
            fn () => AuthenticationLog::with(['user', 'application'])
                ->orderBy('created_at', 'desc')
                ->paginate(15),
            $iterations
        );
        $this->displayStats($authLogStats);

        $this->newLine();
        $this->info('=== Aggregate Query Benchmarks ===');

        // Benchmark: Count queries
        $this->info('Benchmarking: Count aggregations...');
        $countStats = $benchmark->benchmarkIterations(
            'aggregate_counts',
            function () {
                return [
                    'users' => User::count(),
                    'organizations' => Organization::count(),
                    'applications' => Application::count(),
                    'auth_logs' => AuthenticationLog::whereDate('created_at', today())->count(),
                ];
            },
            $iterations
        );
        $this->displayStats($countStats);

        $this->newLine();
        $this->info('=== Complex Query Benchmarks ===');

        // Benchmark: User with all permissions
        $this->info('Benchmarking: User with all permissions...');
        $user = User::with('roles')->first();
        if ($user) {
            $permStats = $benchmark->benchmarkIterations(
                'user_all_permissions',
                fn () => $user->getAllPermissions(),
                $iterations
            );
            $this->displayStats($permStats);
        }

        // Benchmark: Organization statistics
        $this->info('Benchmarking: Organization statistics...');
        $org = Organization::first();
        if ($org) {
            $orgStatStats = $benchmark->benchmarkIterations(
                'organization_statistics',
                fn () => $org->getStatistics(),
                $iterations
            );
            $this->displayStats($orgStatStats);
        }

        $this->newLine();
        $this->info('=== Cache Performance Benchmarks ===');

        // Benchmark: Cache read
        $this->info('Benchmarking: Cache read operation...');
        cache(['test_key' => 'test_value'], 60);
        $cacheReadStats = $benchmark->benchmarkIterations(
            'cache_read',
            fn () => cache('test_key'),
            $iterations
        );
        $this->displayStats($cacheReadStats);

        // Benchmark: Cache write
        $this->info('Benchmarking: Cache write operation...');
        $cacheWriteStats = $benchmark->benchmarkIterations(
            'cache_write',
            fn () => cache(['test_key_'.rand() => 'test_value'], 60),
            $iterations
        );
        $this->displayStats($cacheWriteStats);

        $this->newLine();
        $this->info('=== Summary ===');

        $summary = $benchmark->getSummary();
        $this->table(
            ['Metric', 'Value'],
            [
                ['Total Benchmarks', $summary['total_benchmarks'] ?? 0],
                ['Total Duration (ms)', $summary['total_duration_ms'] ?? 0],
                ['Avg Duration (ms)', $summary['avg_duration_ms'] ?? 0],
                ['Max Duration (ms)', $summary['max_duration_ms'] ?? 0],
                ['Total Memory (MB)', $summary['total_memory_mb'] ?? 0],
                ['Avg Memory (MB)', $summary['avg_memory_mb'] ?? 0],
            ]
        );

        // Export results if requested
        if ($exportFile = $this->option('export')) {
            $this->info("Exporting results to {$exportFile}...");
            $export = $benchmark->export();
            file_put_contents($exportFile, json_encode($export, JSON_PRETTY_PRINT));
            $this->info('✓ Results exported successfully');
        }

        $this->newLine();
        $this->info('✓ Performance benchmarks completed');

        return self::SUCCESS;
    }

    private function displayStats(array $stats): void
    {
        $this->table(
            ['Metric', 'Value'],
            [
                ['Iterations', $stats['iterations']],
                ['Min (ms)', $stats['min_ms']],
                ['Avg (ms)', $stats['avg_ms']],
                ['Median (ms)', $stats['median_ms']],
                ['P95 (ms)', $stats['p95_ms']],
                ['P99 (ms)', $stats['p99_ms']],
                ['Max (ms)', $stats['max_ms']],
            ]
        );

        // Check against performance targets
        $p95Target = config('performance.benchmarks.p95_response_time', 100);
        if ($stats['p95_ms'] > $p95Target) {
            $this->warn("⚠ P95 ({$stats['p95_ms']}ms) exceeds target ({$p95Target}ms)");
        } else {
            $this->info('✓ P95 within target');
        }

        $this->newLine();
    }
}
