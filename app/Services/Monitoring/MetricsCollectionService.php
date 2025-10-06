<?php

namespace App\Services\Monitoring;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class MetricsCollectionService
{
    private const METRICS_TTL = 300; // 5 minutes

    /**
     * Collect all system metrics.
     */
    public function collectAllMetrics(): array
    {
        return [
            'authentication' => $this->getAuthenticationMetrics(),
            'oauth' => $this->getOAuthMetrics(),
            'api' => $this->getApiMetrics(),
            'webhooks' => $this->getWebhookMetrics(),
            'users' => $this->getUserMetrics(),
            'organizations' => $this->getOrganizationMetrics(),
            'mfa' => $this->getMfaMetrics(),
            'performance' => $this->getPerformanceMetrics(),
            'timestamp' => now()->toIso8601String(),
        ];
    }

    /**
     * Get authentication success/failure metrics.
     */
    public function getAuthenticationMetrics(): array
    {
        return Cache::remember('metrics:authentication', self::METRICS_TTL, function () {
            $today = now()->startOfDay();
            $last24Hours = now()->subDay();
            $last7Days = now()->subDays(7);

            // Total authentication attempts
            $totalAttempts = DB::table('authentication_logs')
                ->where('created_at', '>=', $today)
                ->count();

            // Successful logins
            $successfulLogins = DB::table('authentication_logs')
                ->where('created_at', '>=', $today)
                ->where('status', 'success')
                ->count();

            // Failed logins
            $failedLogins = DB::table('authentication_logs')
                ->where('created_at', '>=', $today)
                ->where('status', 'failed')
                ->count();

            // Success rate
            $successRate = $totalAttempts > 0
                ? round(($successfulLogins / $totalAttempts) * 100, 2)
                : 0;

            // Login methods breakdown
            $methodsBreakdown = DB::table('authentication_logs')
                ->select('method', DB::raw('COUNT(*) as count'))
                ->where('created_at', '>=', $today)
                ->groupBy('method')
                ->get()
                ->pluck('count', 'method')
                ->toArray();

            // MFA usage
            $mfaLogins = DB::table('authentication_logs')
                ->where('created_at', '>=', $today)
                ->where('mfa_used', true)
                ->count();

            // Failed login attempts by IP (security monitoring)
            $suspiciousIPs = DB::table('authentication_logs')
                ->select('ip_address', DB::raw('COUNT(*) as attempts'))
                ->where('created_at', '>=', $last24Hours)
                ->where('status', 'failed')
                ->groupBy('ip_address')
                ->having('attempts', '>', 5)
                ->orderByDesc('attempts')
                ->limit(10)
                ->get()
                ->toArray();

            // Trend data (last 7 days)
            $trend = DB::table('authentication_logs')
                ->select(
                    DB::raw('DATE(created_at) as date'),
                    DB::raw('COUNT(*) as total'),
                    DB::raw('SUM(CASE WHEN status = \'success\' THEN 1 ELSE 0 END) as successful'),
                    DB::raw('SUM(CASE WHEN status = \'failed\' THEN 1 ELSE 0 END) as failed')
                )
                ->where('created_at', '>=', $last7Days)
                ->groupBy('date')
                ->orderBy('date')
                ->get()
                ->toArray();

            return [
                'today' => [
                    'total_attempts' => $totalAttempts,
                    'successful' => $successfulLogins,
                    'failed' => $failedLogins,
                    'success_rate' => $successRate,
                    'mfa_used' => $mfaLogins,
                ],
                'methods_breakdown' => $methodsBreakdown,
                'suspicious_ips' => $suspiciousIPs,
                'trend_7_days' => $trend,
            ];
        });
    }

    /**
     * Get OAuth token generation metrics.
     */
    public function getOAuthMetrics(): array
    {
        return Cache::remember('metrics:oauth', self::METRICS_TTL, function () {
            $today = now()->startOfDay();
            $last7Days = now()->subDays(7);

            // Active tokens
            $activeTokens = DB::table('oauth_access_tokens')
                ->where('revoked', false)
                ->where('expires_at', '>', now())
                ->count();

            // Tokens created today
            $tokensToday = DB::table('oauth_access_tokens')
                ->where('created_at', '>=', $today)
                ->count();

            // Revoked tokens today
            $revokedToday = DB::table('oauth_access_tokens')
                ->where('updated_at', '>=', $today)
                ->where('revoked', true)
                ->count();

            // Token by client
            $tokensByClient = DB::table('oauth_access_tokens')
                ->join('oauth_clients', 'oauth_access_tokens.client_id', '=', 'oauth_clients.id')
                ->select('oauth_clients.name', DB::raw('COUNT(*) as count'))
                ->where('oauth_access_tokens.revoked', false)
                ->where('oauth_access_tokens.expires_at', '>', now())
                ->groupBy('oauth_clients.id', 'oauth_clients.name')
                ->orderByDesc('count')
                ->limit(10)
                ->get()
                ->toArray();

            // Refresh token usage
            $refreshTokens = DB::table('oauth_refresh_tokens')
                ->where('revoked', false)
                ->where('expires_at', '>', now())
                ->count();

            // Authorization codes
            $authCodes = DB::table('oauth_auth_codes')
                ->where('revoked', false)
                ->where('expires_at', '>', now())
                ->count();

            // Trend data
            $trend = DB::table('oauth_access_tokens')
                ->select(
                    DB::raw('DATE(created_at) as date'),
                    DB::raw('COUNT(*) as tokens_created')
                )
                ->where('created_at', '>=', $last7Days)
                ->groupBy('date')
                ->orderBy('date')
                ->get()
                ->toArray();

            return [
                'active_tokens' => $activeTokens,
                'tokens_created_today' => $tokensToday,
                'tokens_revoked_today' => $revokedToday,
                'active_refresh_tokens' => $refreshTokens,
                'pending_auth_codes' => $authCodes,
                'tokens_by_client' => $tokensByClient,
                'trend_7_days' => $trend,
            ];
        });
    }

    /**
     * Get API request metrics.
     */
    public function getApiMetrics(): array
    {
        $date = now()->format('Y-m-d');
        $dailyKey = 'api_metrics:'.$date.':daily';

        $metrics = Cache::get($dailyKey, [
            'total_requests' => 0,
            'total_errors' => 0,
            'total_execution_time' => 0,
            'max_execution_time' => 0,
            'min_execution_time' => 0,
            'status_codes' => [],
            'endpoints' => [],
        ]);

        // Calculate averages
        $avgExecutionTime = $metrics['total_requests'] > 0
            ? round($metrics['total_execution_time'] / $metrics['total_requests'], 2)
            : 0;

        $errorRate = $metrics['total_requests'] > 0
            ? round(($metrics['total_errors'] / $metrics['total_requests']) * 100, 2)
            : 0;

        // Get top endpoints
        arsort($metrics['endpoints']);
        $topEndpoints = array_slice($metrics['endpoints'], 0, 10, true);

        return [
            'total_requests' => $metrics['total_requests'],
            'total_errors' => $metrics['total_errors'],
            'error_rate' => $errorRate,
            'avg_response_time_ms' => $avgExecutionTime,
            'max_response_time_ms' => $metrics['max_execution_time'],
            'min_response_time_ms' => $metrics['min_execution_time'],
            'status_codes' => $metrics['status_codes'],
            'top_endpoints' => $topEndpoints,
            'updated_at' => $metrics['updated_at'] ?? null,
        ];
    }

    /**
     * Get webhook delivery metrics.
     */
    public function getWebhookMetrics(): array
    {
        return Cache::remember('metrics:webhooks', self::METRICS_TTL, function () {
            $today = now()->startOfDay();
            $last24Hours = now()->subDay();

            // Total webhooks
            $totalWebhooks = DB::table('webhooks')->count();

            // Active webhooks
            $activeWebhooks = DB::table('webhooks')
                ->where('enabled', true)
                ->count();

            // Deliveries today
            $deliveriesToday = DB::table('webhook_deliveries')
                ->where('created_at', '>=', $today)
                ->count();

            // Successful deliveries
            $successfulDeliveries = DB::table('webhook_deliveries')
                ->where('created_at', '>=', $today)
                ->where('status', 'success')
                ->count();

            // Failed deliveries
            $failedDeliveries = DB::table('webhook_deliveries')
                ->where('created_at', '>=', $today)
                ->where('status', 'failed')
                ->count();

            // Success rate
            $successRate = $deliveriesToday > 0
                ? round(($successfulDeliveries / $deliveriesToday) * 100, 2)
                : 0;

            // Average response time
            $avgResponseTime = DB::table('webhook_deliveries')
                ->where('created_at', '>=', $today)
                ->where('response_time', '>', 0)
                ->avg('response_time');

            // Failed webhooks (multiple failures)
            $problematicWebhooks = DB::table('webhook_deliveries')
                ->select('webhook_id', DB::raw('COUNT(*) as failures'))
                ->where('created_at', '>=', $last24Hours)
                ->where('status', 'failed')
                ->groupBy('webhook_id')
                ->having('failures', '>', 3)
                ->count();

            // Event type breakdown
            $eventBreakdown = DB::table('webhook_deliveries')
                ->select('event_type', DB::raw('COUNT(*) as count'))
                ->where('created_at', '>=', $today)
                ->groupBy('event_type')
                ->get()
                ->pluck('count', 'event_type')
                ->toArray();

            return [
                'total_webhooks' => $totalWebhooks,
                'active_webhooks' => $activeWebhooks,
                'deliveries_today' => $deliveriesToday,
                'successful_deliveries' => $successfulDeliveries,
                'failed_deliveries' => $failedDeliveries,
                'success_rate' => $successRate,
                'avg_response_time_ms' => round($avgResponseTime ?? 0, 2),
                'problematic_webhooks' => $problematicWebhooks,
                'event_breakdown' => $eventBreakdown,
            ];
        });
    }

    /**
     * Get user registration and activity metrics.
     */
    public function getUserMetrics(): array
    {
        return Cache::remember('metrics:users', self::METRICS_TTL, function () {
            $today = now()->startOfDay();
            $last7Days = now()->subDays(7);
            $last30Days = now()->subDays(30);

            // Total users
            $totalUsers = DB::table('users')->count();

            // New registrations
            $newUsersToday = DB::table('users')
                ->where('created_at', '>=', $today)
                ->count();

            $newUsers7Days = DB::table('users')
                ->where('created_at', '>=', $last7Days)
                ->count();

            $newUsers30Days = DB::table('users')
                ->where('created_at', '>=', $last30Days)
                ->count();

            // Active users (logged in recently)
            $activeUsers24h = DB::table('authentication_logs')
                ->where('created_at', '>=', now()->subDay())
                ->where('status', 'success')
                ->distinct('user_id')
                ->count('user_id');

            $activeUsers7Days = DB::table('authentication_logs')
                ->where('created_at', '>=', $last7Days)
                ->where('status', 'success')
                ->distinct('user_id')
                ->count('user_id');

            // MFA enabled users
            $mfaEnabledUsers = DB::table('users')
                ->where('mfa_enabled', true)
                ->count();

            $mfaAdoptionRate = $totalUsers > 0
                ? round(($mfaEnabledUsers / $totalUsers) * 100, 2)
                : 0;

            // User registration trend
            $registrationTrend = DB::table('users')
                ->select(
                    DB::raw('DATE(created_at) as date'),
                    DB::raw('COUNT(*) as count')
                )
                ->where('created_at', '>=', $last7Days)
                ->groupBy('date')
                ->orderBy('date')
                ->get()
                ->toArray();

            return [
                'total_users' => $totalUsers,
                'new_users' => [
                    'today' => $newUsersToday,
                    'last_7_days' => $newUsers7Days,
                    'last_30_days' => $newUsers30Days,
                ],
                'active_users' => [
                    'last_24_hours' => $activeUsers24h,
                    'last_7_days' => $activeUsers7Days,
                ],
                'mfa' => [
                    'enabled_count' => $mfaEnabledUsers,
                    'adoption_rate' => $mfaAdoptionRate,
                ],
                'registration_trend' => $registrationTrend,
            ];
        });
    }

    /**
     * Get organization-level metrics.
     */
    public function getOrganizationMetrics(): array
    {
        return Cache::remember('metrics:organizations', self::METRICS_TTL, function () {
            $today = now()->startOfDay();
            $last7Days = now()->subDays(7);

            // Total organizations
            $totalOrgs = DB::table('organizations')->count();

            // New organizations
            $newOrgsToday = DB::table('organizations')
                ->where('created_at', '>=', $today)
                ->count();

            $newOrgs7Days = DB::table('organizations')
                ->where('created_at', '>=', $last7Days)
                ->count();

            // Organizations by security policy
            $securityPolicies = DB::table('organizations')
                ->select('security_policy', DB::raw('COUNT(*) as count'))
                ->groupBy('security_policy')
                ->get()
                ->pluck('count', 'security_policy')
                ->toArray();

            // Organizations requiring MFA
            $mfaRequiredOrgs = DB::table('organizations')
                ->where('require_mfa', true)
                ->count();

            // Average users per organization
            $avgUsersPerOrg = DB::table('organization_user')
                ->select('organization_id', DB::raw('COUNT(*) as user_count'))
                ->groupBy('organization_id')
                ->avg('user_count');

            // Top organizations by user count
            $topOrgs = DB::table('organization_user')
                ->join('organizations', 'organization_user.organization_id', '=', 'organizations.id')
                ->select('organizations.name', DB::raw('COUNT(*) as user_count'))
                ->groupBy('organization_user.organization_id', 'organizations.name')
                ->orderByDesc('user_count')
                ->limit(10)
                ->get()
                ->toArray();

            return [
                'total_organizations' => $totalOrgs,
                'new_organizations' => [
                    'today' => $newOrgsToday,
                    'last_7_days' => $newOrgs7Days,
                ],
                'security_policies' => $securityPolicies,
                'mfa_required_count' => $mfaRequiredOrgs,
                'avg_users_per_org' => round($avgUsersPerOrg ?? 0, 2),
                'top_organizations' => $topOrgs,
            ];
        });
    }

    /**
     * Get MFA adoption and usage metrics.
     */
    public function getMfaMetrics(): array
    {
        return Cache::remember('metrics:mfa', self::METRICS_TTL, function () {
            $today = now()->startOfDay();
            $last7Days = now()->subDays(7);

            // Total MFA-enabled users
            $mfaEnabledUsers = DB::table('users')
                ->where('mfa_enabled', true)
                ->count();

            // New MFA setups
            $newMfaToday = DB::table('users')
                ->where('mfa_enabled', true)
                ->where('updated_at', '>=', $today)
                ->count();

            $newMfa7Days = DB::table('users')
                ->where('mfa_enabled', true)
                ->where('updated_at', '>=', $last7Days)
                ->count();

            // MFA usage in logins
            $totalLogins = DB::table('authentication_logs')
                ->where('created_at', '>=', $today)
                ->where('status', 'success')
                ->count();

            $mfaLogins = DB::table('authentication_logs')
                ->where('created_at', '>=', $today)
                ->where('status', 'success')
                ->where('mfa_used', true)
                ->count();

            $mfaUsageRate = $totalLogins > 0
                ? round(($mfaLogins / $totalLogins) * 100, 2)
                : 0;

            // MFA setup trend
            $setupTrend = DB::table('users')
                ->select(
                    DB::raw('DATE(updated_at) as date'),
                    DB::raw('COUNT(*) as count')
                )
                ->where('mfa_enabled', true)
                ->where('updated_at', '>=', $last7Days)
                ->groupBy('date')
                ->orderBy('date')
                ->get()
                ->toArray();

            return [
                'enabled_users' => $mfaEnabledUsers,
                'new_setups' => [
                    'today' => $newMfaToday,
                    'last_7_days' => $newMfa7Days,
                ],
                'usage' => [
                    'total_logins_today' => $totalLogins,
                    'mfa_logins_today' => $mfaLogins,
                    'usage_rate' => $mfaUsageRate,
                ],
                'setup_trend' => $setupTrend,
            ];
        });
    }

    /**
     * Get performance metrics.
     */
    public function getPerformanceMetrics(): array
    {
        $date = now()->format('Y-m-d');
        $dailyKey = 'api_metrics:'.$date.':daily';

        $metrics = Cache::get($dailyKey, [
            'total_requests' => 0,
            'total_execution_time' => 0,
            'total_memory_usage' => 0,
            'max_execution_time' => 0,
            'min_execution_time' => PHP_FLOAT_MAX,
        ]);

        // Calculate averages
        $avgExecutionTime = $metrics['total_requests'] > 0
            ? round($metrics['total_execution_time'] / $metrics['total_requests'], 2)
            : 0;

        $avgMemoryUsage = $metrics['total_requests'] > 0
            ? round($metrics['total_memory_usage'] / $metrics['total_requests'], 2)
            : 0;

        // Get slow queries count from performance log
        $slowQueriesCount = $this->getSlowQueriesCount();

        // Get cache hit rate
        $cacheHits = Cache::get('cache_hits', 0);
        $cacheMisses = Cache::get('cache_misses', 0);
        $totalCacheRequests = $cacheHits + $cacheMisses;
        $cacheHitRate = $totalCacheRequests > 0
            ? round(($cacheHits / $totalCacheRequests) * 100, 2)
            : 0;

        return [
            'avg_response_time_ms' => $avgExecutionTime,
            'max_response_time_ms' => $metrics['max_execution_time'],
            'min_response_time_ms' => $metrics['min_execution_time'] === PHP_FLOAT_MAX ? 0 : $metrics['min_execution_time'],
            'avg_memory_usage_bytes' => $avgMemoryUsage,
            'slow_queries_count' => $slowQueriesCount,
            'cache' => [
                'hits' => $cacheHits,
                'misses' => $cacheMisses,
                'hit_rate' => $cacheHitRate,
            ],
        ];
    }

    /**
     * Get slow queries count from logs.
     */
    private function getSlowQueriesCount(): int
    {
        try {
            $logFile = storage_path('logs/performance.log');
            if (! file_exists($logFile)) {
                return 0;
            }

            $content = file_get_contents($logFile);
            $lines = explode("\n", $content);

            $slowQueriesCount = 0;
            foreach ($lines as $line) {
                if (str_contains($line, 'slow query') || str_contains($line, 'Slow query')) {
                    $slowQueriesCount++;
                }
            }

            return $slowQueriesCount;

        } catch (\Exception $e) {
            Log::error('Failed to count slow queries', ['error' => $e->getMessage()]);

            return 0;
        }
    }

    /**
     * Record a custom metric.
     */
    public function recordMetric(string $name, $value, array $tags = []): void
    {
        try {
            $key = 'custom_metric:'.$name.':'.now()->format('Y-m-d');

            $metric = Cache::get($key, [
                'name' => $name,
                'values' => [],
                'tags' => $tags,
                'count' => 0,
                'sum' => 0,
                'min' => PHP_FLOAT_MAX,
                'max' => 0,
            ]);

            $metric['values'][] = $value;
            $metric['count']++;
            $metric['sum'] += $value;
            $metric['min'] = min($metric['min'], $value);
            $metric['max'] = max($metric['max'], $value);

            Cache::put($key, $metric, 86400); // 24 hours

            Log::channel('monitoring')->debug('Metric recorded', [
                'metric' => $name,
                'value' => $value,
                'tags' => $tags,
            ]);

        } catch (\Exception $e) {
            Log::error('Failed to record metric', [
                'metric' => $name,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Get a specific custom metric.
     */
    public function getMetric(string $name, ?string $date = null): ?array
    {
        $date = $date ?? now()->format('Y-m-d');
        $key = 'custom_metric:'.$name.':'.$date;

        return Cache::get($key);
    }
}
