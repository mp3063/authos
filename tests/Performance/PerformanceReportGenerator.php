<?php

namespace Tests\Performance;

use Illuminate\Support\Facades\File;

class PerformanceReportGenerator
{
    private array $results = [];

    private array $baselines = [];

    private string $reportPath;

    public function __construct()
    {
        $this->reportPath = storage_path('app/performance_reports');

        if (! File::exists($this->reportPath)) {
            File::makeDirectory($this->reportPath, 0755, true);
        }

        $this->loadBaselines();
    }

    /**
     * Add test result
     */
    public function addResult(string $testName, array $metrics): void
    {
        $this->results[$testName] = array_merge($metrics, [
            'timestamp' => now()->toIso8601String(),
        ]);
    }

    /**
     * Load baseline measurements
     */
    private function loadBaselines(): void
    {
        $baselineFile = storage_path('app/performance_baselines.json');

        if (File::exists($baselineFile)) {
            $this->baselines = json_decode(File::get($baselineFile), true) ?? [];
        }
    }

    /**
     * Compare current results against baselines
     */
    private function compareWithBaselines(): array
    {
        $comparisons = [];

        foreach ($this->results as $testName => $currentMetrics) {
            if (isset($this->baselines[$testName])) {
                $baseline = $this->baselines[$testName]['metrics'];
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
                            'status' => $this->getComparisonStatus($percentChange),
                        ];
                    }
                }

                $comparisons[$testName] = $comparison;
            }
        }

        return $comparisons;
    }

    /**
     * Get comparison status based on percent change
     */
    private function getComparisonStatus(float $percentChange): string
    {
        $absChange = abs($percentChange);

        if ($percentChange < -10) {
            return 'significantly_improved'; // >10% improvement
        }

        if ($percentChange < -5) {
            return 'improved'; // 5-10% improvement
        }

        if ($absChange <= 5) {
            return 'stable'; // Within 5%
        }

        if ($percentChange <= 10) {
            return 'degraded'; // 5-10% worse
        }

        return 'significantly_degraded'; // >10% worse
    }

    /**
     * Generate comprehensive performance report
     */
    public function generate(): array
    {
        $comparisons = $this->compareWithBaselines();
        $targets = $this->getPhase7Targets();

        $report = [
            'summary' => $this->generateSummary($comparisons, $targets),
            'results' => $this->results,
            'comparisons' => $comparisons,
            'targets' => $targets,
            'target_compliance' => $this->checkTargetCompliance($targets),
            'recommendations' => $this->generateRecommendations($comparisons, $targets),
            'generated_at' => now()->toIso8601String(),
        ];

        // Save reports in multiple formats
        $this->saveJsonReport($report);
        $this->saveHtmlReport($report);
        $this->saveTextReport($report);

        return $report;
    }

    /**
     * Generate executive summary
     */
    private function generateSummary(array $comparisons, array $targets): array
    {
        $totalTests = count($this->results);
        $testsWithBaseline = count($comparisons);
        $improved = 0;
        $degraded = 0;
        $stable = 0;

        foreach ($comparisons as $comparison) {
            foreach ($comparison as $metric) {
                if ($metric['status'] === 'significantly_improved' || $metric['status'] === 'improved') {
                    $improved++;
                } elseif ($metric['status'] === 'significantly_degraded' || $metric['status'] === 'degraded') {
                    $degraded++;
                } else {
                    $stable++;
                }
            }
        }

        return [
            'total_tests' => $totalTests,
            'tests_with_baseline' => $testsWithBaseline,
            'improved_metrics' => $improved,
            'degraded_metrics' => $degraded,
            'stable_metrics' => $stable,
            'overall_health' => $this->calculateOverallHealth($improved, $degraded, $stable),
        ];
    }

    /**
     * Calculate overall health score
     */
    private function calculateOverallHealth(int $improved, int $degraded, int $stable): string
    {
        $total = $improved + $degraded + $stable;

        if ($total === 0) {
            return 'unknown';
        }

        $improvedPercent = ($improved / $total) * 100;
        $degradedPercent = ($degraded / $total) * 100;

        if ($improvedPercent > 50 && $degradedPercent < 10) {
            return 'excellent';
        }

        if ($improvedPercent > 30 && $degradedPercent < 20) {
            return 'good';
        }

        if ($degradedPercent < 30) {
            return 'fair';
        }

        return 'poor';
    }

    /**
     * Check compliance with Phase 7 targets
     */
    private function checkTargetCompliance(array $targets): array
    {
        $compliance = [];

        foreach ($this->results as $testName => $metrics) {
            foreach ($targets as $targetKey => $targetValue) {
                // Map target keys to metric keys
                $metricKey = $this->mapTargetToMetric($targetKey);

                if (isset($metrics[$metricKey])) {
                    $isCompliant = $this->checkCompliance($metrics[$metricKey], $targetValue, $targetKey);

                    $compliance[$testName][$targetKey] = [
                        'target' => $targetValue,
                        'actual' => $metrics[$metricKey],
                        'compliant' => $isCompliant,
                        'margin' => $this->calculateMargin($metrics[$metricKey], $targetValue, $targetKey),
                    ];
                }
            }
        }

        return $compliance;
    }

    /**
     * Map target key to metric key
     */
    private function mapTargetToMetric(string $targetKey): string
    {
        $mapping = [
            'auth_response_time_p95' => 'p95_response_time_ms',
            'user_management_response_time_p95' => 'p95_response_time_ms',
            'oauth_token_generation_p95' => 'p95_response_time_ms',
            'bulk_operations_1000_records' => 'duration_ms',
            'cache_hit_ratio_min' => 'hit_ratio_percent',
            'queries_per_request_max' => 'avg_query_count',
            'memory_per_request_max' => 'avg_memory_mb',
            'compression_ratio_min' => 'compression_ratio_percent',
        ];

        return $mapping[$targetKey] ?? $targetKey;
    }

    /**
     * Check if metric meets target
     */
    private function checkCompliance($actual, $target, string $targetKey): bool
    {
        // For "max" targets, actual should be less than target
        if (str_contains($targetKey, 'max')) {
            return $actual <= $target;
        }

        // For "min" targets, actual should be greater than target
        if (str_contains($targetKey, 'min')) {
            return $actual >= $target;
        }

        // For "p95" or duration targets, actual should be less than target
        return $actual <= $target;
    }

    /**
     * Calculate margin from target
     */
    private function calculateMargin($actual, $target, string $targetKey): float
    {
        if (str_contains($targetKey, 'max') || str_contains($targetKey, 'p95')) {
            // Lower is better
            return (($target - $actual) / $target) * 100;
        }

        // Higher is better (for "min" targets)
        return (($actual - $target) / $target) * 100;
    }

    /**
     * Generate recommendations
     */
    private function generateRecommendations(array $comparisons, array $targets): array
    {
        $recommendations = [];

        // Check for degraded performance
        foreach ($comparisons as $testName => $comparison) {
            foreach ($comparison as $metricName => $data) {
                if ($data['status'] === 'significantly_degraded') {
                    $recommendations[] = [
                        'severity' => 'high',
                        'test' => $testName,
                        'metric' => $metricName,
                        'message' => "Performance degradation detected in {$testName} - {$metricName} has degraded by {$data['percent_change']}%",
                        'suggestion' => $this->getSuggestion($metricName, $data),
                    ];
                } elseif ($data['status'] === 'degraded') {
                    $recommendations[] = [
                        'severity' => 'medium',
                        'test' => $testName,
                        'metric' => $metricName,
                        'message' => "Minor performance degradation in {$testName} - {$metricName} has degraded by {$data['percent_change']}%",
                        'suggestion' => $this->getSuggestion($metricName, $data),
                    ];
                }
            }
        }

        // Check for target violations
        $compliance = $this->checkTargetCompliance($targets);
        foreach ($compliance as $testName => $targetChecks) {
            foreach ($targetChecks as $targetName => $data) {
                if (! $data['compliant']) {
                    $recommendations[] = [
                        'severity' => 'high',
                        'test' => $testName,
                        'metric' => $targetName,
                        'message' => "Target violation: {$targetName} failed (actual: {$data['actual']}, target: {$data['target']})",
                        'suggestion' => $this->getTargetSuggestion($targetName),
                    ];
                }
            }
        }

        return $recommendations;
    }

    /**
     * Get suggestion for metric improvement
     */
    private function getSuggestion(string $metricName, array $data): string
    {
        $suggestions = [
            'duration_ms' => 'Consider optimizing database queries, adding indexes, or implementing caching',
            'memory_used_mb' => 'Review memory usage patterns, implement lazy loading, or use chunking for large datasets',
            'query_count' => 'Implement eager loading, reduce N+1 queries, or add query result caching',
            'compression_ratio_percent' => 'Verify compression middleware is enabled and configured correctly',
            'hit_ratio_percent' => 'Review cache configuration, increase cache TTL, or implement cache warming',
        ];

        foreach ($suggestions as $key => $suggestion) {
            if (str_contains($metricName, $key)) {
                return $suggestion;
            }
        }

        return 'Review recent code changes and performance optimization strategies';
    }

    /**
     * Get suggestion for target compliance
     */
    private function getTargetSuggestion(string $targetName): string
    {
        $suggestions = [
            'auth_response_time_p95' => 'Optimize authentication queries, implement session caching, or review rate limiting configuration',
            'user_management_response_time_p95' => 'Add database indexes, implement pagination, or use eager loading for relationships',
            'oauth_token_generation_p95' => 'Optimize token generation process, implement token caching, or review encryption overhead',
            'bulk_operations_1000_records' => 'Implement batch processing, use database transactions, or process records in chunks',
            'cache_hit_ratio_min' => 'Increase cache TTL, implement cache warming, or review cache invalidation strategy',
            'queries_per_request_max' => 'Implement eager loading, add query result caching, or optimize ORM relationships',
            'memory_per_request_max' => 'Implement lazy loading, use database chunking, or optimize collection processing',
            'compression_ratio_min' => 'Enable gzip compression, review response payload size, or implement field selection',
        ];

        return $suggestions[$targetName] ?? 'Review performance optimization strategies for this metric';
    }

    /**
     * Get Phase 7 performance targets
     */
    private function getPhase7Targets(): array
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

    /**
     * Save JSON report
     */
    private function saveJsonReport(array $report): void
    {
        $filename = $this->reportPath.'/performance_report_'.now()->format('Y-m-d_His').'.json';
        File::put($filename, json_encode($report, JSON_PRETTY_PRINT));
    }

    /**
     * Save HTML report
     */
    private function saveHtmlReport(array $report): void
    {
        $html = $this->generateHtmlReport($report);
        $filename = $this->reportPath.'/performance_report_'.now()->format('Y-m-d_His').'.html';
        File::put($filename, $html);
    }

    /**
     * Save text report
     */
    private function saveTextReport(array $report): void
    {
        $text = $this->generateTextReport($report);
        $filename = $this->reportPath.'/performance_report_'.now()->format('Y-m-d_His').'.txt';
        File::put($filename, $text);
    }

    /**
     * Generate HTML report
     */
    private function generateHtmlReport(array $report): string
    {
        $summary = $report['summary'];
        $healthColor = match ($summary['overall_health']) {
            'excellent' => '#22c55e',
            'good' => '#84cc16',
            'fair' => '#eab308',
            'poor' => '#ef4444',
            default => '#6b7280',
        };

        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report - {$report['generated_at']}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f9fafb; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        h1 { color: #111827; border-bottom: 3px solid {$healthColor}; padding-bottom: 16px; }
        h2 { color: #374151; margin-top: 32px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 24px 0; }
        .metric-card { background: #f3f4f6; padding: 20px; border-radius: 6px; border-left: 4px solid {$healthColor}; }
        .metric-value { font-size: 32px; font-weight: bold; color: #111827; }
        .metric-label { font-size: 14px; color: #6b7280; margin-top: 8px; }
        .health-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; background: {$healthColor}; color: white; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
        th { background: #f9fafb; font-weight: 600; color: #374151; }
        .improved { color: #22c55e; }
        .degraded { color: #ef4444; }
        .stable { color: #6b7280; }
        .compliant { color: #22c55e; font-weight: 600; }
        .non-compliant { color: #ef4444; font-weight: 600; }
        .recommendation { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; margin: 12px 0; border-radius: 4px; }
        .recommendation.high { background: #fee2e2; border-left-color: #ef4444; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AuthOS Performance Test Report</h1>
        <p><strong>Generated:</strong> {$report['generated_at']}</p>
        <p><strong>Overall Health:</strong> <span class="health-badge">{$summary['overall_health']}</span></p>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="metric-card">
                <div class="metric-value">{$summary['total_tests']}</div>
                <div class="metric-label">Total Tests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{$summary['improved_metrics']}</div>
                <div class="metric-label">Improved Metrics</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{$summary['degraded_metrics']}</div>
                <div class="metric-label">Degraded Metrics</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{$summary['stable_metrics']}</div>
                <div class="metric-label">Stable Metrics</div>
            </div>
        </div>
HTML;

        // Add recommendations
        if (! empty($report['recommendations'])) {
            $html .= '<h2>Recommendations</h2>';
            foreach ($report['recommendations'] as $rec) {
                $html .= "<div class='recommendation {$rec['severity']}'>";
                $html .= "<strong>[{$rec['severity']}]</strong> {$rec['message']}<br>";
                $html .= "<em>Suggestion:</em> {$rec['suggestion']}";
                $html .= '</div>';
            }
        }

        $html .= <<<'HTML'
        <div class="footer">
            <p>AuthOS Performance Testing Suite | Phase 7 Optimization Validation</p>
        </div>
    </div>
</body>
</html>
HTML;

        return $html;
    }

    /**
     * Generate text report
     */
    private function generateTextReport(array $report): string
    {
        $text = "=================================================================\n";
        $text .= "                AuthOS Performance Test Report\n";
        $text .= "=================================================================\n\n";
        $text .= "Generated: {$report['generated_at']}\n\n";

        // Summary
        $summary = $report['summary'];
        $text .= "EXECUTIVE SUMMARY\n";
        $text .= "-----------------------------------------------------------------\n";
        $text .= sprintf("Overall Health: %s\n", strtoupper($summary['overall_health']));
        $text .= sprintf("Total Tests: %d\n", $summary['total_tests']);
        $text .= sprintf("Improved Metrics: %d\n", $summary['improved_metrics']);
        $text .= sprintf("Degraded Metrics: %d\n", $summary['degraded_metrics']);
        $text .= sprintf("Stable Metrics: %d\n\n", $summary['stable_metrics']);

        // Recommendations
        if (! empty($report['recommendations'])) {
            $text .= "RECOMMENDATIONS\n";
            $text .= "-----------------------------------------------------------------\n";
            foreach ($report['recommendations'] as $rec) {
                $text .= sprintf("[%s] %s\n", strtoupper($rec['severity']), $rec['message']);
                $text .= sprintf("   Suggestion: %s\n\n", $rec['suggestion']);
            }
        }

        $text .= "=================================================================\n";

        return $text;
    }
}
