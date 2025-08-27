<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;

class AlertingService
{
    /**
     * Check system health and send alerts if needed.
     */
    public function checkHealthAlerts(): void
    {
        $healthChecks = [
            'high_error_rate' => $this->checkErrorRate(),
            'slow_response_time' => $this->checkResponseTime(),
            'high_memory_usage' => $this->checkMemoryUsage(),
            'oauth_token_issues' => $this->checkOAuthIssues(),
        ];

        foreach ($healthChecks as $alertType => $alert) {
            if ($alert['triggered']) {
                $this->sendAlert($alertType, $alert);
            }
        }
    }

    /**
     * Check for high error rates.
     */
    private function checkErrorRate(): array
    {
        $date = now()->format('Y-m-d');
        $hour = now()->format('H');
        
        // Check last hour metrics
        $hourlyKey = 'api_metrics:' . $date . ':hourly:' . $hour;
        $metrics = Cache::get($hourlyKey, []);

        $totalRequests = $metrics['total_requests'] ?? 0;
        $totalErrors = $metrics['total_errors'] ?? 0;
        $errorRate = $totalRequests > 0 ? ($totalErrors / $totalRequests) * 100 : 0;

        $threshold = 10; // 10% error rate threshold
        
        return [
            'triggered' => $errorRate > $threshold && $totalRequests > 10, // Minimum requests to avoid false positives
            'value' => $errorRate,
            'threshold' => $threshold,
            'message' => "API error rate is {$errorRate}% (threshold: {$threshold}%)",
            'details' => [
                'total_requests' => $totalRequests,
                'total_errors' => $totalErrors,
                'period' => 'last hour',
            ],
        ];
    }

    /**
     * Check for slow response times.
     */
    private function checkResponseTime(): array
    {
        $date = now()->format('Y-m-d');
        $hour = now()->format('H');
        
        // Check last hour metrics
        $hourlyKey = 'api_metrics:' . $date . ':hourly:' . $hour;
        $metrics = Cache::get($hourlyKey, []);

        $totalRequests = $metrics['total_requests'] ?? 0;
        $totalExecutionTime = $metrics['total_execution_time'] ?? 0;
        $avgResponseTime = $totalRequests > 0 ? $totalExecutionTime / $totalRequests : 0;

        $threshold = 2000; // 2 seconds threshold
        
        return [
            'triggered' => $avgResponseTime > $threshold && $totalRequests > 5,
            'value' => $avgResponseTime,
            'threshold' => $threshold,
            'message' => "Average API response time is {$avgResponseTime}ms (threshold: {$threshold}ms)",
            'details' => [
                'avg_response_time' => $avgResponseTime,
                'max_response_time' => $metrics['max_execution_time'] ?? 0,
                'total_requests' => $totalRequests,
                'period' => 'last hour',
            ],
        ];
    }

    /**
     * Check for high memory usage.
     */
    private function checkMemoryUsage(): array
    {
        $currentUsage = memory_get_usage(true);
        $memoryLimit = $this->parseMemoryLimit(ini_get('memory_limit'));
        $usagePercentage = ($currentUsage / $memoryLimit) * 100;

        $threshold = 85; // 85% memory usage threshold
        
        return [
            'triggered' => $usagePercentage > $threshold,
            'value' => $usagePercentage,
            'threshold' => $threshold,
            'message' => "Memory usage is {$usagePercentage}% (threshold: {$threshold}%)",
            'details' => [
                'current_usage' => $currentUsage,
                'memory_limit' => $memoryLimit,
                'peak_usage' => memory_get_peak_usage(true),
            ],
        ];
    }

    /**
     * Check for OAuth token issues.
     */
    private function checkOAuthIssues(): array
    {
        try {
            // Check for unusually high number of token revocations
            $recentRevocations = \Laravel\Passport\Token::where('revoked', true)
                ->where('updated_at', '>', now()->subHour())
                ->count();

            $threshold = 50; // 50 revocations per hour threshold
            
            return [
                'triggered' => $recentRevocations > $threshold,
                'value' => $recentRevocations,
                'threshold' => $threshold,
                'message' => "High number of token revocations: {$recentRevocations} in the last hour (threshold: {$threshold})",
                'details' => [
                    'recent_revocations' => $recentRevocations,
                    'period' => 'last hour',
                ],
            ];
        } catch (\Exception $e) {
            return [
                'triggered' => true,
                'value' => null,
                'threshold' => null,
                'message' => "OAuth health check failed: " . $e->getMessage(),
                'details' => [
                    'error' => $e->getMessage(),
                ],
            ];
        }
    }

    /**
     * Send alert notification.
     */
    private function sendAlert(string $alertType, array $alert): void
    {
        $alertKey = 'alert_sent:' . $alertType . ':' . now()->format('Y-m-d-H');
        
        // Prevent spam - only send one alert per type per hour
        if (Cache::has($alertKey)) {
            return;
        }

        Log::critical('System Alert Triggered', [
            'alert_type' => $alertType,
            'message' => $alert['message'],
            'details' => $alert['details'],
            'timestamp' => now()->toISOString(),
        ]);

        // Mark alert as sent for this hour
        Cache::put($alertKey, true, 3600);

        // Here you could send email, Slack notification, etc.
        $this->sendEmailAlert($alertType, $alert);
    }

    /**
     * Send email alert (if configured).
     */
    private function sendEmailAlert(string $alertType, array $alert): void
    {
        $adminEmails = config('monitoring.alert_emails', []);
        
        if (empty($adminEmails)) {
            return;
        }

        try {
            // You would implement actual email sending here
            Log::info('Alert email would be sent', [
                'recipients' => $adminEmails,
                'alert_type' => $alertType,
                'message' => $alert['message'],
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to send alert email', [
                'error' => $e->getMessage(),
                'alert_type' => $alertType,
            ]);
        }
    }

    /**
     * Parse memory limit string to bytes.
     */
    private function parseMemoryLimit(string $memoryLimit): int
    {
        $unit = strtolower($memoryLimit[strlen($memoryLimit) - 1]);
        $value = (int)$memoryLimit;

        switch ($unit) {
            case 'g':
                $value *= 1024 * 1024 * 1024;
                break;
            case 'm':
                $value *= 1024 * 1024;
                break;
            case 'k':
                $value *= 1024;
                break;
        }

        return $value;
    }

    /**
     * Get current system status summary.
     */
    public function getSystemStatusSummary(): array
    {
        $checks = [
            'error_rate' => $this->checkErrorRate(),
            'response_time' => $this->checkResponseTime(),
            'memory_usage' => $this->checkMemoryUsage(),
            'oauth_health' => $this->checkOAuthIssues(),
        ];

        $activeAlerts = collect($checks)->filter(function ($check) {
            return $check['triggered'];
        });

        return [
            'overall_status' => $activeAlerts->isEmpty() ? 'healthy' : 'warning',
            'active_alerts' => $activeAlerts->count(),
            'checks' => $checks,
            'timestamp' => now()->toISOString(),
        ];
    }
}