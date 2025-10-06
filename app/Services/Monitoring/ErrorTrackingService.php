<?php

namespace App\Services\Monitoring;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Throwable;

class ErrorTrackingService
{
    public const SEVERITY_CRITICAL = 'critical';

    public const SEVERITY_ERROR = 'error';

    public const SEVERITY_WARNING = 'warning';

    public const SEVERITY_INFO = 'info';

    /**
     * Track an error with categorization.
     */
    public function trackError(
        Throwable $exception,
        string $severity = self::SEVERITY_ERROR,
        array $context = []
    ): void {
        $errorId = $this->generateErrorId($exception);

        $errorData = [
            'id' => $errorId,
            'severity' => $severity,
            'message' => $exception->getMessage(),
            'exception' => get_class($exception),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'code' => $exception->getCode(),
            'trace' => $this->sanitizeTrace($exception->getTrace()),
            'context' => $context,
            'timestamp' => now()->toIso8601String(),
            'environment' => config('app.env'),
        ];

        // Log error to appropriate channel
        $this->logError($errorData);

        // Store error for monitoring
        $this->storeError($errorData);

        // Trigger alerts if critical
        if ($severity === self::SEVERITY_CRITICAL) {
            $this->triggerCriticalAlert($errorData);
        }

        // Check error rate and trigger alerts if threshold exceeded
        $this->checkErrorRate();
    }

    /**
     * Track a failed authentication attempt.
     */
    public function trackFailedAuthentication(
        string $email,
        string $ip,
        string $reason,
        array $context = []
    ): void {
        $data = array_merge([
            'type' => 'failed_authentication',
            'email' => $email,
            'ip' => $ip,
            'reason' => $reason,
            'timestamp' => now()->toIso8601String(),
        ], $context);

        Log::channel('security')->warning('Failed authentication attempt', $data);

        // Increment failed attempts counter
        $this->incrementFailedAttempts($ip, $email);

        // Check for brute force attack
        $this->checkBruteForce($ip, $email);
    }

    /**
     * Track a webhook delivery failure.
     */
    public function trackWebhookFailure(
        int $webhookId,
        int $deliveryId,
        string $error,
        array $context = []
    ): void {
        $data = array_merge([
            'type' => 'webhook_failure',
            'webhook_id' => $webhookId,
            'delivery_id' => $deliveryId,
            'error' => $error,
            'timestamp' => now()->toIso8601String(),
        ], $context);

        Log::channel('monitoring')->warning('Webhook delivery failed', $data);

        // Increment failure counter
        $this->incrementWebhookFailures($webhookId);

        // Check if webhook should be disabled
        $this->checkWebhookHealth($webhookId);
    }

    /**
     * Get error statistics.
     */
    public function getErrorStatistics(?string $date = null): array
    {
        $date = $date ?? now()->format('Y-m-d');
        $key = 'error_stats:'.$date;

        return Cache::get($key, [
            'critical' => 0,
            'error' => 0,
            'warning' => 0,
            'info' => 0,
            'total' => 0,
            'by_type' => [],
            'by_hour' => [],
        ]);
    }

    /**
     * Get recent errors.
     */
    public function getRecentErrors(int $limit = 50): array
    {
        $errors = [];
        $recentErrorsKey = 'recent_errors';

        $storedErrors = Cache::get($recentErrorsKey, []);

        return array_slice($storedErrors, 0, $limit);
    }

    /**
     * Get error rate (errors per minute).
     */
    public function getErrorRate(): float
    {
        $key = 'error_rate:'.now()->format('Y-m-d:H:i');
        $count = Cache::get($key, 0);

        return round($count / 60, 2); // errors per second
    }

    /**
     * Check if error rate exceeds threshold.
     */
    public function checkErrorRate(): void
    {
        $errorRate = $this->getErrorRate();
        $threshold = config('monitoring.error_rate_threshold', 10); // 10 errors per minute

        if ($errorRate > $threshold) {
            $this->triggerErrorRateAlert($errorRate, $threshold);
        }
    }

    /**
     * Generate unique error ID.
     */
    private function generateErrorId(Throwable $exception): string
    {
        $hash = md5(
            get_class($exception).
            $exception->getMessage().
            $exception->getFile().
            $exception->getLine()
        );

        return 'err_'.substr($hash, 0, 12).'_'.time();
    }

    /**
     * Sanitize stack trace for logging.
     */
    private function sanitizeTrace(array $trace): array
    {
        // Limit trace to 10 frames
        $trace = array_slice($trace, 0, 10);

        // Remove sensitive data
        foreach ($trace as &$frame) {
            if (isset($frame['args'])) {
                $frame['args'] = array_map(function ($arg) {
                    if (is_object($arg)) {
                        return get_class($arg);
                    }
                    if (is_array($arg) && count($arg) > 5) {
                        return '[array with '.count($arg).' items]';
                    }

                    return $arg;
                }, $frame['args']);
            }
        }

        return $trace;
    }

    /**
     * Log error to appropriate channel.
     */
    private function logError(array $errorData): void
    {
        $severity = $errorData['severity'];
        $context = [
            'error_id' => $errorData['id'],
            'exception' => $errorData['exception'],
            'message' => $errorData['message'],
            'file' => $errorData['file'],
            'line' => $errorData['line'],
            'context' => $errorData['context'],
        ];

        switch ($severity) {
            case self::SEVERITY_CRITICAL:
                Log::channel('monitoring')->critical($errorData['message'], $context);
                break;
            case self::SEVERITY_ERROR:
                Log::channel('monitoring')->error($errorData['message'], $context);
                break;
            case self::SEVERITY_WARNING:
                Log::channel('monitoring')->warning($errorData['message'], $context);
                break;
            default:
                Log::channel('monitoring')->info($errorData['message'], $context);
        }
    }

    /**
     * Store error for monitoring and analytics.
     */
    private function storeError(array $errorData): void
    {
        try {
            $date = now()->format('Y-m-d');
            $hour = now()->format('H');

            // Update error statistics
            $statsKey = 'error_stats:'.$date;
            $stats = Cache::get($statsKey, [
                'critical' => 0,
                'error' => 0,
                'warning' => 0,
                'info' => 0,
                'total' => 0,
                'by_type' => [],
                'by_hour' => array_fill(0, 24, 0),
            ]);

            $stats[$errorData['severity']]++;
            $stats['total']++;
            $stats['by_type'][$errorData['exception']] = ($stats['by_type'][$errorData['exception']] ?? 0) + 1;
            $stats['by_hour'][(int) $hour]++;

            Cache::put($statsKey, $stats, 86400); // 24 hours

            // Store in recent errors list
            $recentErrorsKey = 'recent_errors';
            $recentErrors = Cache::get($recentErrorsKey, []);
            array_unshift($recentErrors, $errorData);

            // Keep only last 100 errors
            $recentErrors = array_slice($recentErrors, 0, 100);
            Cache::put($recentErrorsKey, $recentErrors, 3600); // 1 hour

            // Increment error rate counter
            $rateKey = 'error_rate:'.now()->format('Y-m-d:H:i');
            Cache::increment($rateKey, 1);
            Cache::put($rateKey, Cache::get($rateKey, 1), 60); // 1 minute

        } catch (\Exception $e) {
            // Silently fail to avoid infinite loop
            Log::debug('Failed to store error statistics', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Trigger critical error alert.
     */
    private function triggerCriticalAlert(array $errorData): void
    {
        try {
            Log::channel('monitoring')->critical('CRITICAL ERROR ALERT', $errorData);

            // In production, send email/Slack notification
            if (config('app.env') === 'production') {
                $adminEmail = config('monitoring.alert_email');
                if ($adminEmail) {
                    // Send email notification
                    // Mail::to($adminEmail)->send(new CriticalErrorAlert($errorData));
                }

                $slackWebhook = config('monitoring.slack_webhook_url');
                if ($slackWebhook) {
                    // Send Slack notification
                    // Notification::route('slack', $slackWebhook)->notify(new CriticalErrorNotification($errorData));
                }
            }

        } catch (\Exception $e) {
            Log::debug('Failed to send critical alert', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Trigger error rate alert.
     */
    private function triggerErrorRateAlert(float $rate, float $threshold): void
    {
        $key = 'error_rate_alert:'.now()->format('Y-m-d:H');

        // Only alert once per hour
        if (Cache::has($key)) {
            return;
        }

        Cache::put($key, true, 3600); // 1 hour

        Log::channel('monitoring')->critical('Error rate threshold exceeded', [
            'current_rate' => $rate,
            'threshold' => $threshold,
            'timestamp' => now()->toIso8601String(),
        ]);

        // Send notification (email/Slack)
        // Implementation would be similar to triggerCriticalAlert
    }

    /**
     * Increment failed authentication attempts counter.
     */
    private function incrementFailedAttempts(string $ip, string $email): void
    {
        $ipKey = 'failed_auth:ip:'.$ip.':'.now()->format('Y-m-d:H');
        $emailKey = 'failed_auth:email:'.md5($email).':'.now()->format('Y-m-d:H');

        Cache::increment($ipKey, 1);
        Cache::put($ipKey, Cache::get($ipKey, 1), 3600); // 1 hour

        Cache::increment($emailKey, 1);
        Cache::put($emailKey, Cache::get($emailKey, 1), 3600); // 1 hour
    }

    /**
     * Check for brute force attacks.
     */
    private function checkBruteForce(string $ip, string $email): void
    {
        $ipKey = 'failed_auth:ip:'.$ip.':'.now()->format('Y-m-d:H');
        $emailKey = 'failed_auth:email:'.md5($email).':'.now()->format('Y-m-d:H');

        $ipAttempts = Cache::get($ipKey, 0);
        $emailAttempts = Cache::get($emailKey, 0);

        $threshold = config('monitoring.brute_force_threshold', 10);

        if ($ipAttempts > $threshold) {
            $this->triggerBruteForceAlert('IP', $ip, $ipAttempts);
        }

        if ($emailAttempts > $threshold) {
            $this->triggerBruteForceAlert('Email', $email, $emailAttempts);
        }
    }

    /**
     * Trigger brute force alert.
     */
    private function triggerBruteForceAlert(string $type, string $identifier, int $attempts): void
    {
        $key = 'brute_force_alert:'.$type.':'.md5($identifier).':'.now()->format('Y-m-d:H');

        // Only alert once per hour
        if (Cache::has($key)) {
            return;
        }

        Cache::put($key, true, 3600); // 1 hour

        Log::channel('security')->critical('Potential brute force attack detected', [
            'type' => $type,
            'identifier' => $type === 'IP' ? $identifier : md5($identifier),
            'attempts' => $attempts,
            'timestamp' => now()->toIso8601String(),
        ]);
    }

    /**
     * Increment webhook failure counter.
     */
    private function incrementWebhookFailures(int $webhookId): void
    {
        $key = 'webhook_failures:'.$webhookId.':'.now()->format('Y-m-d');

        Cache::increment($key, 1);
        Cache::put($key, Cache::get($key, 1), 86400); // 24 hours
    }

    /**
     * Check webhook health and trigger alerts.
     */
    private function checkWebhookHealth(int $webhookId): void
    {
        $key = 'webhook_failures:'.$webhookId.':'.now()->format('Y-m-d');
        $failures = Cache::get($key, 0);

        $threshold = config('monitoring.webhook_failure_threshold', 50);

        if ($failures > $threshold) {
            $this->triggerWebhookHealthAlert($webhookId, $failures);
        }
    }

    /**
     * Trigger webhook health alert.
     */
    private function triggerWebhookHealthAlert(int $webhookId, int $failures): void
    {
        $key = 'webhook_health_alert:'.$webhookId.':'.now()->format('Y-m-d');

        // Only alert once per day
        if (Cache::has($key)) {
            return;
        }

        Cache::put($key, true, 86400); // 24 hours

        Log::channel('monitoring')->critical('Webhook experiencing high failure rate', [
            'webhook_id' => $webhookId,
            'failures_today' => $failures,
            'timestamp' => now()->toIso8601String(),
        ]);
    }

    /**
     * Clear error statistics.
     */
    public function clearStatistics(?string $date = null): void
    {
        $date = $date ?? now()->format('Y-m-d');
        $key = 'error_stats:'.$date;

        Cache::forget($key);
    }

    /**
     * Get error trends (last 7 days).
     */
    public function getErrorTrends(int $days = 7): array
    {
        $trends = [];

        for ($i = 0; $i < $days; $i++) {
            $date = now()->subDays($i)->format('Y-m-d');
            $stats = $this->getErrorStatistics($date);

            $trends[] = [
                'date' => $date,
                'critical' => $stats['critical'],
                'error' => $stats['error'],
                'warning' => $stats['warning'],
                'total' => $stats['total'],
            ];
        }

        return array_reverse($trends);
    }
}
