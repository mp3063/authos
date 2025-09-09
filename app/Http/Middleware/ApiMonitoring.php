<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class ApiMonitoring
{
    /**
     * Handle an incoming request and log metrics.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $startTime = microtime(true);
        $startMemory = memory_get_usage(true);

        // Get user info for monitoring
        $user = auth('api')->user();
        $userId = $user ? $user->id : null;
        $userEmail = $user ? $user->email : null;

        // Generate request ID for tracing
        $requestId = $this->generateRequestId();
        $request->headers->set('X-Request-ID', $requestId);

        // Log request start
        Log::channel('api')->info('API Request Started', [
            'request_id' => $requestId,
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'path' => $request->path(),
            'user_id' => $userId,
            'user_email' => $userEmail,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'content_length' => $request->header('content-length'),
            'accept' => $request->header('accept'),
            'timestamp' => now()->toISOString(),
        ]);

        // Process request
        $response = $next($request);

        // Calculate performance metrics
        $executionTime = round((microtime(true) - $startTime) * 1000, 2); // ms
        $memoryUsage = memory_get_usage(true) - $startMemory;
        $responseSize = strlen($response->getContent());

        // Log response
        Log::channel('api')->info('API Request Completed', [
            'request_id' => $requestId,
            'status_code' => $response->getStatusCode(),
            'execution_time_ms' => $executionTime,
            'memory_usage_bytes' => $memoryUsage,
            'response_size_bytes' => $responseSize,
            'cache_status' => $response->headers->get('X-Cache', 'NONE'),
            'timestamp' => now()->toISOString(),
        ]);

        // Store metrics for analytics
        $this->storeMetrics($request, $response, $executionTime, $memoryUsage, $responseSize, $userId);

        // Log errors if any
        if ($response->getStatusCode() >= 400) {
            Log::channel('api')->warning('API Request Error', [
                'request_id' => $requestId,
                'status_code' => $response->getStatusCode(),
                'method' => $request->method(),
                'path' => $request->path(),
                'user_id' => $userId,
                'ip_address' => $request->ip(),
                'response_body' => $this->getSafeResponseBody($response),
            ]);
        }

        // Add monitoring headers to response
        $response->headers->set('X-Request-ID', $requestId);
        $response->headers->set('X-Response-Time', $executionTime.'ms');
        $response->headers->set('X-Memory-Usage', $this->formatBytes($memoryUsage));

        return $response;
    }

    /**
     * Generate unique request ID.
     */
    private function generateRequestId(): string
    {
        return 'req_'.uniqid().'_'.str_pad(dechex(mt_rand(0, 0xFFFF)), 4, '0', STR_PAD_LEFT);
    }

    /**
     * Store metrics in cache for analytics.
     */
    private function storeMetrics(
        Request $request,
        Response $response,
        float $executionTime,
        int $memoryUsage,
        int $responseSize,
        ?int $userId
    ): void {
        $date = now()->format('Y-m-d');
        $hour = now()->format('H');
        $minute = now()->format('i');

        // Store metrics with different granularities
        $baseKey = 'api_metrics:'.$date;

        // Daily metrics
        $dailyKey = $baseKey.':daily';
        $this->incrementMetrics($dailyKey, $request, $response, $executionTime, $memoryUsage, $responseSize, $userId, 86400);

        // Hourly metrics
        $hourlyKey = $baseKey.':hourly:'.$hour;
        $this->incrementMetrics($hourlyKey, $request, $response, $executionTime, $memoryUsage, $responseSize, $userId, 3600);

        // 5-minute metrics for real-time monitoring
        $minuteBlock = floor((int) $minute / 5) * 5;
        $realtimeKey = $baseKey.':realtime:'.$hour.':'.str_pad($minuteBlock, 2, '0', STR_PAD_LEFT);
        $this->incrementMetrics($realtimeKey, $request, $response, $executionTime, $memoryUsage, $responseSize, $userId, 300);
    }

    /**
     * Increment metrics in cache.
     */
    private function incrementMetrics(
        string $key,
        Request $request,
        Response $response,
        float $executionTime,
        int $memoryUsage,
        int $responseSize,
        ?int $userId,
        int $ttl
    ): void {
        try {
            $metrics = Cache::get($key, [
                'total_requests' => 0,
                'total_errors' => 0,
                'total_execution_time' => 0,
                'total_memory_usage' => 0,
                'total_response_size' => 0,
                'max_execution_time' => 0,
                'min_execution_time' => PHP_FLOAT_MAX,
                'status_codes' => [],
                'endpoints' => [],
                'unique_users' => [],
                'user_agents' => [],
                'updated_at' => null,
            ]);

            // Update metrics
            $metrics['total_requests']++;
            $metrics['total_execution_time'] += $executionTime;
            $metrics['total_memory_usage'] += $memoryUsage;
            $metrics['total_response_size'] += $responseSize;
            $metrics['max_execution_time'] = max($metrics['max_execution_time'], $executionTime);
            $metrics['min_execution_time'] = min($metrics['min_execution_time'], $executionTime);
            $metrics['updated_at'] = now()->toISOString();

            if ($response->getStatusCode() >= 400) {
                $metrics['total_errors']++;
            }

            // Track status codes
            $statusCode = (string) $response->getStatusCode();
            $metrics['status_codes'][$statusCode] = ($metrics['status_codes'][$statusCode] ?? 0) + 1;

            // Track endpoints
            $endpoint = $request->method().' '.$request->path();
            $metrics['endpoints'][$endpoint] = ($metrics['endpoints'][$endpoint] ?? 0) + 1;

            // Track unique users (limit to preserve memory)
            if ($userId && count($metrics['unique_users']) < 1000) {
                $metrics['unique_users'][$userId] = true;
            }

            // Track user agents (limit to top 10)
            $userAgent = $this->simplifyUserAgent($request->userAgent());
            if ($userAgent) {
                $metrics['user_agents'][$userAgent] = ($metrics['user_agents'][$userAgent] ?? 0) + 1;
                if (count($metrics['user_agents']) > 10) {
                    arsort($metrics['user_agents']);
                    $metrics['user_agents'] = array_slice($metrics['user_agents'], 0, 10, true);
                }
            }

            Cache::put($key, $metrics, $ttl);

        } catch (\Exception $e) {
            Log::error('Failed to store API metrics', [
                'error' => $e->getMessage(),
                'key' => $key,
            ]);
        }
    }

    /**
     * Get safe response body for logging (truncated and sanitized).
     */
    private function getSafeResponseBody(Response $response): string
    {
        $content = $response->getContent();

        if (strlen($content) > 1000) {
            $content = substr($content, 0, 1000).'... [truncated]';
        }

        // Remove sensitive data patterns
        $content = preg_replace('/("password"|"token"|"secret"|"key"):\s*"[^"]*"/', '"$1": "[REDACTED]"', $content);

        return $content;
    }

    /**
     * Format bytes for human reading.
     */
    private function formatBytes(int $bytes): string
    {
        if ($bytes >= 1048576) {
            return round($bytes / 1048576, 2).'MB';
        } elseif ($bytes >= 1024) {
            return round($bytes / 1024, 2).'KB';
        }

        return $bytes.'B';
    }

    /**
     * Simplify user agent for grouping.
     */
    private function simplifyUserAgent(?string $userAgent): ?string
    {
        if (! $userAgent) {
            return null;
        }

        // Extract browser/client name
        if (preg_match('/Chrome\/[\d.]+/', $userAgent)) {
            return 'Chrome';
        } elseif (preg_match('/Firefox\/[\d.]+/', $userAgent)) {
            return 'Firefox';
        } elseif (preg_match('/Safari\/[\d.]+/', $userAgent)) {
            return 'Safari';
        } elseif (preg_match('/Postman/', $userAgent)) {
            return 'Postman';
        } elseif (preg_match('/curl/', $userAgent)) {
            return 'cURL';
        } elseif (preg_match('/Insomnia/', $userAgent)) {
            return 'Insomnia';
        }

        return 'Other';
    }
}
