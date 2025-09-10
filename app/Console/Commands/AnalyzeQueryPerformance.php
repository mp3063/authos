<?php

namespace App\Console\Commands;

use App\Services\PerformanceMonitoringService;
use Illuminate\Console\Command;

class AnalyzeQueryPerformance extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'performance:analyze 
                            {--hours=24 : Hours of data to analyze}
                            {--recommendations : Show optimization recommendations}';

    /**
     * The console command description.
     */
    protected $description = 'Analyze query performance and provide optimization recommendations';

    /**
     * Execute the console command.
     */
    public function handle(PerformanceMonitoringService $performanceService)
    {
        $hours = (int) $this->option('hours');
        $showRecommendations = $this->option('recommendations');

        $this->info("Analyzing query performance for the last {$hours} hours...");

        // Enable query logging
        $performanceService->startQueryMonitoring();

        // Get performance statistics
        $stats = $performanceService->getPerformanceStats($hours);

        // Display API performance metrics
        $this->table(
            ['Metric', 'Value'],
            [
                ['Average Response Time', $stats['api_performance']['average_response_time'].'ms'],
                ['P95 Response Time', $stats['api_performance']['p95_response_time'].'ms'],
                ['P99 Response Time', $stats['api_performance']['p99_response_time'].'ms'],
                ['Total Requests', number_format($stats['api_performance']['total_requests'])],
                ['Error Rate', $stats['api_performance']['error_rate'].'%'],
                ['Throughput', $stats['api_performance']['throughput'].' req/min'],
            ]
        );

        // Display database performance metrics
        $this->newLine();
        $this->info('Database Performance:');
        $this->table(
            ['Metric', 'Value'],
            [
                ['Average Query Time', $stats['database_performance']['average_query_time'].'ms'],
                ['Slow Query Count', number_format($stats['database_performance']['slow_query_count'])],
                ['Total Queries', number_format($stats['database_performance']['total_queries'])],
                ['Cache Hit Rate', $stats['database_performance']['cache_hit_rate'].'%'],
            ]
        );

        // Display top slow endpoints
        if (! empty($stats['top_slow_endpoints'])) {
            $this->newLine();
            $this->info('Top 5 Slowest Endpoints:');
            $endpointData = collect($stats['top_slow_endpoints'])
                ->take(5)
                ->map(function ($endpoint) {
                    return [
                        $endpoint['endpoint'],
                        $endpoint['average_time'].'ms',
                        $endpoint['total_requests'],
                        $endpoint['error_rate'].'%',
                    ];
                });

            $this->table(
                ['Endpoint', 'Avg Time', 'Requests', 'Error Rate'],
                $endpointData->toArray()
            );
        }

        // Show optimization recommendations if requested
        if ($showRecommendations) {
            $this->newLine();
            $this->info('Optimization Recommendations:');

            $recommendations = $performanceService->getOptimizationRecommendations();

            if (empty($recommendations)) {
                $this->info('✅ No performance issues detected!');
            } else {
                foreach ($recommendations as $rec) {
                    $priority = match ($rec['priority']) {
                        'high' => '🔴',
                        'medium' => '🟡',
                        'low' => '🟢',
                        default => '⚪'
                    };

                    $this->line("{$priority} {$rec['issue']}");
                    $this->line("   Description: {$rec['description']}");
                    $this->line("   Suggestion: {$rec['suggestion']}");
                    $this->newLine();
                }
            }
        }

        // Provide database query analysis
        $this->newLine();
        $this->info('Recent Query Analysis:');

        // Analyze a sample query
        $sampleQuery = 'SELECT * FROM users WHERE organization_id = ? AND is_active = 1 LIMIT 10';
        $analysis = $performanceService->analyzeQuery($sampleQuery, [1]);

        if (! empty($analysis['recommendations'])) {
            foreach ($analysis['recommendations'] as $recommendation) {
                $this->warn("• {$recommendation}");
            }
        } else {
            $this->info('✅ Sample queries appear to be optimized');
        }

        $this->newLine();
        $this->info('Performance analysis complete!');

        return Command::SUCCESS;
    }
}
