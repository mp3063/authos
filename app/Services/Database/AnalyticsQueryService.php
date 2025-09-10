<?php

namespace App\Services\Database;

use App\Models\Organization;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * High-performance analytics queries with optimized database operations
 */
class AnalyticsQueryService
{
    /**
     * Get comprehensive organization analytics using Laravel query builder
     */
    public function getOrganizationAnalytics(Organization $organization, array $filters = []): array
    {
        $startDate = isset($filters['start_date'])
            ? Carbon::parse($filters['start_date'])->startOfDay()
            : Carbon::now()->subDays(30)->startOfDay();

        $endDate = isset($filters['end_date'])
            ? Carbon::parse($filters['end_date'])->endOfDay()
            : Carbon::now()->endOfDay();

        // User statistics using Eloquent relationships
        $totalUsers = $organization->users()->count();
        $activeUsers = $organization->users()->where('is_active', true)->count();
        $newUsers = $organization->users()->where('created_at', '>=', $startDate)->count();
        $mfaUsers = $organization->users()->whereNotNull('mfa_methods')->count();

        // Application statistics
        $totalApps = $organization->applications()->count();
        $activeApps = $organization->applications()->where('is_active', true)->count();
        $ssoEnabledApps = $organization->applications()
            ->whereHas('ssoConfiguration')
            ->count();

        // Authentication statistics using query builder
        $authQuery = DB::table('authentication_logs')
            ->join('users', 'authentication_logs.user_id', '=', 'users.id')
            ->where('users.organization_id', $organization->id)
            ->whereBetween('authentication_logs.created_at', [$startDate, $endDate]);

        $successfulLogins = (clone $authQuery)->where('event', 'login_success')->count();
        $failedLogins = (clone $authQuery)->where('event', 'login_failed')->count();
        $uniqueActiveUsers = (clone $authQuery)->distinct('authentication_logs.user_id')->count('authentication_logs.user_id');
        $uniqueIps = (clone $authQuery)->distinct('authentication_logs.ip_address')->count('authentication_logs.ip_address');
        $uniqueUserAgents = (clone $authQuery)->distinct('authentication_logs.user_agent')->count('authentication_logs.user_agent');

        // Invitation statistics
        $pendingInvitations = $organization->invitations()->where('status', 'pending')->count();
        $acceptedInPeriod = $organization->invitations()
            ->where('status', 'accepted')
            ->where('accepted_at', '>=', $startDate)
            ->count();
        $expiredInvitations = $organization->invitations()->where('status', 'expired')->count();

        // Calculate derived metrics
        $totalAuthAttempts = $successfulLogins + $failedLogins;
        $successRate = $totalAuthAttempts > 0
            ? round(($successfulLogins / $totalAuthAttempts) * 100, 2)
            : 0;

        return [
            'period' => [
                'start_date' => $startDate->toDateString(),
                'end_date' => $endDate->toDateString(),
                'days' => $startDate->diffInDays($endDate) + 1,
            ],
            'users' => [
                'total' => $totalUsers,
                'active' => $activeUsers,
                'new_in_period' => $newUsers,
                'mfa_enabled' => $mfaUsers,
                'mfa_adoption_rate' => $totalUsers > 0
                    ? round(($mfaUsers / $totalUsers) * 100, 2)
                    : 0,
            ],
            'applications' => [
                'total' => $totalApps,
                'active' => $activeApps,
                'sso_enabled' => $ssoEnabledApps,
                'sso_adoption_rate' => $totalApps > 0
                    ? round(($ssoEnabledApps / $totalApps) * 100, 2)
                    : 0,
            ],
            'authentication' => [
                'successful_logins' => $successfulLogins,
                'failed_logins' => $failedLogins,
                'success_rate' => $successRate,
                'unique_active_users' => $uniqueActiveUsers,
                'unique_ip_addresses' => $uniqueIps,
                'unique_user_agents' => $uniqueUserAgents,
                'average_logins_per_user' => $uniqueActiveUsers > 0
                    ? round($successfulLogins / $uniqueActiveUsers, 2)
                    : 0,
            ],
            'invitations' => [
                'pending' => $pendingInvitations,
                'accepted_in_period' => $acceptedInPeriod,
                'expired' => $expiredInvitations,
            ],
        ];
    }

    /**
     * Get daily activity trends with optimized query
     */
    public function getDailyActivityTrends(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        $results = DB::select('
            SELECT 
                DATE(al.created_at) as activity_date,
                COUNT(CASE WHEN al.event = "login_success" THEN 1 END) as successful_logins,
                COUNT(CASE WHEN al.event = "login_failed" THEN 1 END) as failed_logins,
                COUNT(DISTINCT al.user_id) as unique_users,
                COUNT(DISTINCT al.application_id) as unique_applications,
                AVG(CASE WHEN al.event = "login_success" THEN 1.0 ELSE 0.0 END) as success_rate
            FROM authentication_logs al
            JOIN users u ON al.user_id = u.id  
            WHERE u.organization_id = ? 
                AND al.created_at >= ?
            GROUP BY DATE(al.created_at)
            ORDER BY activity_date DESC
        ', [$organization->id, $startDate]);

        return array_map(function ($row) {
            return [
                'date' => $row->activity_date,
                'successful_logins' => (int) $row->successful_logins,
                'failed_logins' => (int) $row->failed_logins,
                'unique_users' => (int) $row->unique_users,
                'unique_applications' => (int) $row->unique_applications,
                'success_rate' => round($row->success_rate * 100, 2),
            ];
        }, $results);
    }

    /**
     * Get application usage analytics efficiently
     */
    public function getApplicationUsageAnalytics(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        $results = DB::select('
            SELECT 
                a.id,
                a.name,
                a.client_id,
                a.is_active,
                COUNT(DISTINCT ua.user_id) as total_users,
                COUNT(DISTINCT CASE WHEN ua.last_login_at >= ? THEN ua.user_id END) as active_users,
                COALESCE(SUM(ua.login_count), 0) as total_logins,
                COALESCE(MAX(ua.last_login_at), a.created_at) as latest_activity,
                COUNT(DISTINCT al.id) as auth_events_period,
                COUNT(DISTINCT CASE WHEN al.event = "login_success" THEN al.id END) as successful_logins_period,
                COUNT(DISTINCT CASE WHEN al.event = "login_failed" THEN al.id END) as failed_logins_period
            FROM applications a
            LEFT JOIN user_applications ua ON a.id = ua.application_id
            LEFT JOIN authentication_logs al ON a.id = al.application_id AND al.created_at >= ?
            WHERE a.organization_id = ?
            GROUP BY a.id, a.name, a.client_id, a.is_active, a.created_at
            ORDER BY active_users DESC, total_logins DESC
        ', [$startDate, $startDate, $organization->id]);

        return array_map(function ($row) {
            $successRate = ($row->successful_logins_period + $row->failed_logins_period) > 0
                ? round(($row->successful_logins_period / ($row->successful_logins_period + $row->failed_logins_period)) * 100, 2)
                : 0;

            return [
                'id' => (int) $row->id,
                'name' => $row->name,
                'client_id' => $row->client_id,
                'is_active' => (bool) $row->is_active,
                'total_users' => (int) $row->total_users,
                'active_users' => (int) $row->active_users,
                'total_logins' => (int) $row->total_logins,
                'latest_activity' => $row->latest_activity,
                'auth_events_period' => (int) $row->auth_events_period,
                'success_rate_period' => $successRate,
                'activity_score' => ($row->active_users * 2) + ($row->total_logins * 0.1),
            ];
        }, $results);
    }

    /**
     * Get security analytics and risk metrics
     */
    public function getSecurityAnalytics(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        $results = DB::select('
            SELECT 
                COUNT(DISTINCT CASE WHEN al.event = "login_failed" THEN al.ip_address END) as suspicious_ips,
                COUNT(DISTINCT CASE WHEN al.event = "login_failed" THEN al.user_id END) as users_with_failed_attempts,
                COUNT(CASE WHEN al.event = "login_failed" THEN 1 END) as total_failed_attempts,
                COUNT(CASE WHEN al.event = "login_success" THEN 1 END) as total_successful_logins,
                COUNT(DISTINCT CASE WHEN al.event IN ("mfa_challenge_sent", "mfa_verified") THEN al.user_id END) as mfa_active_users,
                COUNT(CASE WHEN al.event = "mfa_failed" THEN 1 END) as mfa_failed_attempts,
                COUNT(DISTINCT al.ip_address) as total_unique_ips,
                COUNT(DISTINCT al.user_agent) as total_unique_agents
            FROM authentication_logs al
            JOIN users u ON al.user_id = u.id
            WHERE u.organization_id = ? AND al.created_at >= ?
        ', [$organization->id, $startDate]);

        $data = (array) $results[0];

        // Get top risky IPs
        $riskyIps = DB::select('
            SELECT 
                al.ip_address,
                COUNT(CASE WHEN al.event = "login_failed" THEN 1 END) as failed_attempts,
                COUNT(CASE WHEN al.event = "login_success" THEN 1 END) as successful_attempts,
                COUNT(DISTINCT al.user_id) as targeted_users,
                MAX(al.created_at) as latest_attempt
            FROM authentication_logs al
            JOIN users u ON al.user_id = u.id
            WHERE u.organization_id = ? 
                AND al.created_at >= ?
                AND al.event IN ("login_failed", "login_success")
            GROUP BY al.ip_address
            HAVING failed_attempts >= 3
            ORDER BY failed_attempts DESC, targeted_users DESC
            LIMIT 20
        ', [$organization->id, $startDate]);

        return [
            'period' => [
                'start_date' => $startDate->toDateString(),
                'days' => $days,
            ],
            'threat_metrics' => [
                'suspicious_ips' => (int) $data['suspicious_ips'],
                'users_with_failed_attempts' => (int) $data['users_with_failed_attempts'],
                'total_failed_attempts' => (int) $data['total_failed_attempts'],
                'attack_success_rate' => $data['total_failed_attempts'] > 0
                    ? round(($data['total_successful_logins'] / ($data['total_failed_attempts'] + $data['total_successful_logins'])) * 100, 2)
                    : 0,
                'total_unique_ips' => (int) $data['total_unique_ips'],
                'total_unique_agents' => (int) $data['total_unique_agents'],
            ],
            'mfa_metrics' => [
                'active_mfa_users' => (int) $data['mfa_active_users'],
                'mfa_failed_attempts' => (int) $data['mfa_failed_attempts'],
            ],
            'risky_ips' => array_map(function ($row) {
                $totalAttempts = $row->failed_attempts + $row->successful_attempts;

                return [
                    'ip_address' => $row->ip_address,
                    'failed_attempts' => (int) $row->failed_attempts,
                    'successful_attempts' => (int) $row->successful_attempts,
                    'targeted_users' => (int) $row->targeted_users,
                    'risk_score' => round(($row->failed_attempts * 2) + ($row->targeted_users * 1.5), 2),
                    'success_rate' => $totalAttempts > 0 ? round(($row->successful_attempts / $totalAttempts) * 100, 2) : 0,
                    'latest_attempt' => $row->latest_attempt,
                ];
            }, $riskyIps),
        ];
    }

    /**
     * Get role and permission analytics
     */
    public function getRoleAnalytics(Organization $organization): array
    {
        $results = DB::select('
            SELECT 
                r.name as role_name,
                COUNT(DISTINCT mhr.model_id) as user_count,
                COUNT(DISTINCT rhp.permission_id) as permission_count,
                AVG(CASE WHEN u.is_active = 1 THEN 1.0 ELSE 0.0 END) as active_user_rate,
                MAX(u.last_login_at) as latest_user_login
            FROM roles r
            LEFT JOIN model_has_roles mhr ON r.id = mhr.role_id AND mhr.model_type = ?
            LEFT JOIN users u ON mhr.model_id = u.id AND u.organization_id = ?
            LEFT JOIN role_has_permissions rhp ON r.id = rhp.role_id
            WHERE r.name NOT LIKE "system.%"
            GROUP BY r.id, r.name
            ORDER BY user_count DESC
        ', ['App\\Models\\User', $organization->id]);

        return array_map(function ($row) {
            return [
                'role_name' => $row->role_name,
                'user_count' => (int) $row->user_count,
                'permission_count' => (int) $row->permission_count,
                'active_user_rate' => round($row->active_user_rate * 100, 2),
                'latest_user_login' => $row->latest_user_login,
                'utilization_score' => ($row->user_count * 2) + ($row->permission_count * 0.5),
            ];
        }, $results);
    }

    /**
     * Get comprehensive activity heat map data
     */
    public function getActivityHeatMap(Organization $organization, int $days = 7): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        $results = DB::select('
            SELECT 
                DATE(al.created_at) as activity_date,
                HOUR(al.created_at) as activity_hour,
                COUNT(CASE WHEN al.event = "login_success" THEN 1 END) as login_count,
                COUNT(DISTINCT al.user_id) as unique_users,
                COUNT(DISTINCT al.application_id) as unique_apps
            FROM authentication_logs al
            JOIN users u ON al.user_id = u.id
            WHERE u.organization_id = ? 
                AND al.created_at >= ?
                AND al.event = "login_success"
            GROUP BY DATE(al.created_at), HOUR(al.created_at)
            ORDER BY activity_date DESC, activity_hour ASC
        ', [$organization->id, $startDate]);

        $heatMap = [];
        foreach ($results as $row) {
            $heatMap[$row->activity_date][$row->activity_hour] = [
                'login_count' => (int) $row->login_count,
                'unique_users' => (int) $row->unique_users,
                'unique_apps' => (int) $row->unique_apps,
                'intensity' => min(($row->login_count / 10) * 100, 100), // Scale to 0-100
            ];
        }

        return $heatMap;
    }
}
