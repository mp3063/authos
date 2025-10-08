<?php

namespace App\Console\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Symfony\Component\Process\Process;
use Tests\Performance\PerformanceReportGenerator;

class RunPerformanceTests extends Command
{
    protected $signature = 'performance:test
                           {--suite=all : Test suite to run (all, api, cache, database, compression, memory, throughput, bulk)}
                           {--report : Generate detailed report after tests}
                           {--baseline : Record new baseline measurements}';

    protected $description = 'Run performance tests and generate reports';

    private array $results = [];

    public function handle(): int
    {
        $this->info('AuthOS Performance Test Suite');
        $this->newLine();

        // Prepare environment
        $this->prepareEnvironment();

        // Run tests based on suite
        $suite = $this->option('suite');

        match ($suite) {
            'api' => $this->runApiTests(),
            'cache' => $this->runCacheTests(),
            'database' => $this->runDatabaseTests(),
            'compression' => $this->runCompressionTests(),
            'memory' => $this->runMemoryTests(),
            'throughput' => $this->runThroughputTests(),
            'bulk' => $this->runBulkTests(),
            default => $this->runAllTests(),
        };

        // Generate report if requested
        if ($this->option('report')) {
            $this->generateReport();
        }

        // Show summary
        $this->showSummary();

        $this->newLine();
        $this->info('Performance testing complete!');

        return self::SUCCESS;
    }

    private function prepareEnvironment(): void
    {
        $this->info('Preparing test environment...');

        Artisan::call('config:clear');
        Artisan::call('cache:clear');

        $this->info('✓ Environment ready');
        $this->newLine();
    }

    private function runAllTests(): void
    {
        $this->info('Running all performance tests...');
        $this->newLine();

        $this->runApiTests();
        $this->runBulkTests();
        $this->runCacheTests();
        $this->runCompressionTests();
        $this->runDatabaseTests();
        $this->runMemoryTests();
        $this->runThroughputTests();
    }

    private function runApiTests(): void
    {
        $this->info('→ API Response Time Tests');
        $this->runPhpUnit('ApiResponseTimeTest');
    }

    private function runBulkTests(): void
    {
        $this->info('→ Bulk Operations Performance Tests');
        $this->runPhpUnit('BulkOperationsPerformanceTest');
    }

    private function runCacheTests(): void
    {
        $this->info('→ Cache Performance Tests');
        $this->runPhpUnit('CacheEffectivenessTest');
        $this->runPhpUnit('CachePerformanceTest');
    }

    private function runCompressionTests(): void
    {
        $this->info('→ Compression Performance Tests');
        $this->runPhpUnit('CompressionPerformanceTest');
    }

    private function runDatabaseTests(): void
    {
        $this->info('→ Database Query Performance Tests');
        $this->runPhpUnit('DatabaseQueryPerformanceTest');
    }

    private function runMemoryTests(): void
    {
        $this->info('→ Memory Usage Tests');
        $this->runPhpUnit('MemoryUsageTest');
    }

    private function runThroughputTests(): void
    {
        $this->info('→ Throughput Tests');
        $this->runPhpUnit('ThroughputTest');
    }

    private function runPhpUnit(string $filter): void
    {
        $command = [
            base_path('vendor/bin/phpunit'),
            '--testsuite=Performance',
            "--filter=$filter",
            '--no-coverage',
        ];

        $process = new Process($command);
        $process->setTimeout(300); // 5 minutes timeout
        $process->run(function ($type, $buffer) {
            if ($this->output->isVerbose()) {
                $this->output->write($buffer);
            }
        });

        if ($process->isSuccessful()) {
            $this->results[$filter] = 'passed';
            $this->info("  ✓ $filter completed");
        } else {
            $this->results[$filter] = 'failed';
            $this->error("  ✗ $filter failed");
        }

        $this->newLine();
    }

    private function generateReport(): void
    {
        $this->info('Generating performance report...');

        $generator = new PerformanceReportGenerator;

        try {
            $report = $generator->generate();

            $this->newLine();
            $this->info('✓ Report generated successfully');
            $this->newLine();

            // Show report summary
            $summary = $report['summary'];
            $this->table(
                ['Metric', 'Value'],
                [
                    ['Total Tests', $summary['total_tests']],
                    ['Tests with Baseline', $summary['tests_with_baseline']],
                    ['Improved Metrics', $summary['improved_metrics']],
                    ['Degraded Metrics', $summary['degraded_metrics']],
                    ['Stable Metrics', $summary['stable_metrics']],
                    ['Overall Health', strtoupper($summary['overall_health'])],
                ]
            );

            // Show recommendations
            if (! empty($report['recommendations'])) {
                $this->newLine();
                $this->warn('Recommendations:');
                foreach (array_slice($report['recommendations'], 0, 5) as $rec) {
                    $this->line("  [{$rec['severity']}] {$rec['message']}");
                }

                if (count($report['recommendations']) > 5) {
                    $this->line('  ... and '.(count($report['recommendations']) - 5).' more');
                }
            }

            // Show report file locations
            $reportDir = storage_path('app/performance_reports');
            $latestReport = collect(File::files($reportDir))
                ->sortByDesc(fn ($file) => $file->getMTime())
                ->first();

            if ($latestReport) {
                $this->newLine();
                $this->info("Report saved to: {$latestReport->getPathname()}");
            }
        } catch (Exception $e) {
            $this->error('Failed to generate report: '.$e->getMessage());
        }
    }

    private function showSummary(): void
    {
        $this->newLine();
        $this->info('=== Test Results Summary ===');
        $this->newLine();

        $passed = count(array_filter($this->results, fn ($r) => $r === 'passed'));
        $failed = count(array_filter($this->results, fn ($r) => $r === 'failed'));
        $total = count($this->results);

        $this->table(
            ['Status', 'Count'],
            [
                ['Passed', $passed],
                ['Failed', $failed],
                ['Total', $total],
            ]
        );

        // Show Phase 7 targets
        $this->newLine();
        $this->info('=== Phase 7 Performance Targets ===');
        $this->table(
            ['Metric', 'Target'],
            [
                ['Authentication P95 response time', '< 100ms'],
                ['User management P95 response time', '< 150ms'],
                ['OAuth token generation P95', '< 200ms'],
                ['Bulk operations (1000 records)', '< 5 seconds'],
                ['Cache hit ratio', '>= 80%'],
                ['Queries per request', '<= 10'],
                ['Memory per request', '<= 20MB'],
                ['Compression ratio', '>= 60%'],
            ]
        );

        // Next steps
        $this->newLine();
        $this->info('Next Steps:');
        $this->line('  1. Review detailed reports in storage/app/performance_reports/');
        $this->line('  2. Run K6 load tests: k6 run tests/Performance/k6/authentication-load.js');
        $this->line('  3. Address any performance issues identified');
        $this->line('  4. Re-run tests to validate improvements');
    }
}
