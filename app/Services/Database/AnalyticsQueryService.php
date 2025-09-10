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
     * Get daily activity trends with optimized query using collections
     */
    public function getDailyActivityTrends(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        // Get raw authentication logs for the organization
        $logs = DB::table('authentication_logs as al')
            ->join('users as u', 'al.user_id', '=', 'u.id')
            ->where('u.organization_id', $organization->id)
            ->where('al.created_at', '>=', $startDate)
            ->select([
                'al.created_at',
                'al.event',
                'al.user_id',
                'al.application_id',
            ])
            ->get();

        // Use collections to group and aggregate data
        return $logs->groupBy(function ($log) {
            return Carbon::parse($log->created_at)->toDateString();
        })->map(function ($dayLogs, $date) {
            $successfulLogins = $dayLogs->where('event', 'login_success')->count();
            $failedLogins = $dayLogs->where('event', 'login_failed')->count();
            $uniqueUsers = $dayLogs->pluck('user_id')->unique()->count();
            $uniqueApplications = $dayLogs->pluck('application_id')->unique()->count();
            $totalAttempts = $successfulLogins + $failedLogins;

            return [
                'date' => $date,
                'successful_logins' => $successfulLogins,
                'failed_logins' => $failedLogins,
                'unique_users' => $uniqueUsers,
                'unique_applications' => $uniqueApplications,
                'success_rate' => $totalAttempts > 0 ? round(($successfulLogins / $totalAttempts) * 100, 2) : 0,
            ];
        })->sortByDesc('date')->values()->toArray();
    }

    /**
     * Get application usage analytics using collections
     */
    public function getApplicationUsageAnalytics(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        // Get applications with basic info
        $applications = DB::table('applications')
            ->where('organization_id', $organization->id)
            ->select(['id', 'name', 'client_id', 'is_active', 'created_at'])
            ->get()
            ->keyBy('id');

        // Get user application relationships
        $userApplications = DB::table('user_applications')
            ->whereIn('application_id', $applications->keys())
            ->select(['application_id', 'user_id', 'last_login_at', 'login_count'])
            ->get()
            ->groupBy('application_id');

        // Get authentication logs for the period
        $authLogs = DB::table('authentication_logs')
            ->whereIn('application_id', $applications->keys())
            ->where('created_at', '>=', $startDate)
            ->select(['application_id', 'event', 'id'])
            ->get()
            ->groupBy('application_id');

        return $applications->map(function ($app) use ($userApplications, $authLogs, $startDate) {
            $appUserRelations = collect($userApplications->get($app->id, []));
            $appAuthLogs = collect($authLogs->get($app->id, []));

            // Calculate metrics using collections
            $totalUsers = $appUserRelations->pluck('user_id')->unique()->count();
            $activeUsers = $appUserRelations->filter(function ($relation) use ($startDate) {
                return $relation->last_login_at && Carbon::parse($relation->last_login_at)->gte($startDate);
            })->pluck('user_id')->unique()->count();

            $totalLogins = $appUserRelations->sum('login_count') ?? 0;
            $latestActivity = $appUserRelations->max('last_login_at') ?? $app->created_at;

            $authEventsCount = $appAuthLogs->count();
            $successfulLogins = $appAuthLogs->where('event', 'login_success')->count();
            $failedLogins = $appAuthLogs->where('event', 'login_failed')->count();
            $totalAttempts = $successfulLogins + $failedLogins;

            return [
                'id' => (int) $app->id,
                'name' => $app->name,
                'client_id' => $app->client_id,
                'is_active' => (bool) $app->is_active,
                'total_users' => $totalUsers,
                'active_users' => $activeUsers,
                'total_logins' => $totalLogins,
                'latest_activity' => $latestActivity,
                'auth_events_period' => $authEventsCount,
                'success_rate_period' => $totalAttempts > 0 ? round(($successfulLogins / $totalAttempts) * 100, 2) : 0,
                'activity_score' => ($activeUsers * 2) + ($totalLogins * 0.1),
            ];
        })->sortByDesc('active_users')
            ->sortByDesc('total_logins')
            ->values()
            ->toArray();
    }

    /**
     * Get security analytics using collections for data processing
     */
    public function getSecurityAnalytics(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        // Get all authentication logs for the period
        $logs = DB::table('authentication_logs as al')
            ->join('users as u', 'al.user_id', '=', 'u.id')
            ->where('u.organization_id', $organization->id)
            ->where('al.created_at', '>=', $startDate)
            ->select([
                'al.event',
                'al.ip_address',
                'al.user_agent',
                'al.user_id',
                'al.created_at',
            ])
            ->get();

        // Process security metrics using collections
        $failedLogs = $logs->where('event', 'login_failed');
        $successfulLogs = $logs->where('event', 'login_success');
        $mfaLogs = $logs->whereIn('event', ['mfa_challenge_sent', 'mfa_verified']);
        $mfaFailedLogs = $logs->where('event', 'mfa_failed');

        // Calculate threat metrics
        $suspiciousIps = $failedLogs->pluck('ip_address')->unique()->count();
        $usersWithFailedAttempts = $failedLogs->pluck('user_id')->unique()->count();
        $totalFailedAttempts = $failedLogs->count();
        $totalSuccessfulLogins = $successfulLogs->count();
        $totalUniqueIps = $logs->pluck('ip_address')->unique()->count();
        $totalUniqueAgents = $logs->pluck('user_agent')->unique()->count();
        $mfaActiveUsers = $mfaLogs->pluck('user_id')->unique()->count();
        $mfaFailedAttempts = $mfaFailedLogs->count();

        // Get risky IPs using collections
        $ipAnalysis = $logs->whereIn('event', ['login_failed', 'login_success'])
            ->groupBy('ip_address')
            ->map(function ($ipLogs, $ip) {
                $failedAttempts = $ipLogs->where('event', 'login_failed')->count();
                $successfulAttempts = $ipLogs->where('event', 'login_success')->count();
                $targetedUsers = $ipLogs->pluck('user_id')->unique()->count();
                $latestAttempt = $ipLogs->max('created_at');

                return [
                    'ip_address' => $ip,
                    'failed_attempts' => $failedAttempts,
                    'successful_attempts' => $successfulAttempts,
                    'targeted_users' => $targetedUsers,
                    'latest_attempt' => $latestAttempt,
                ];
            })
            ->filter(function ($ipData) {
                return $ipData['failed_attempts'] >= 3; // Only risky IPs
            })
            ->sortByDesc('failed_attempts')
            ->sortByDesc('targeted_users')
            ->take(20);

        return [
            'period' => [
                'start_date' => $startDate->toDateString(),
                'days' => $days,
            ],
            'threat_metrics' => [
                'suspicious_ips' => $suspiciousIps,
                'users_with_failed_attempts' => $usersWithFailedAttempts,
                'total_failed_attempts' => $totalFailedAttempts,
                'attack_success_rate' => ($totalFailedAttempts + $totalSuccessfulLogins) > 0
                    ? round(($totalSuccessfulLogins / ($totalFailedAttempts + $totalSuccessfulLogins)) * 100, 2)
                    : 0,
                'total_unique_ips' => $totalUniqueIps,
                'total_unique_agents' => $totalUniqueAgents,
            ],
            'mfa_metrics' => [
                'active_mfa_users' => $mfaActiveUsers,
                'mfa_failed_attempts' => $mfaFailedAttempts,
            ],
            'risky_ips' => $ipAnalysis->map(function ($ipData) {
                $totalAttempts = $ipData['failed_attempts'] + $ipData['successful_attempts'];

                return [
                    'ip_address' => $ipData['ip_address'],
                    'failed_attempts' => $ipData['failed_attempts'],
                    'successful_attempts' => $ipData['successful_attempts'],
                    'targeted_users' => $ipData['targeted_users'],
                    'risk_score' => round(($ipData['failed_attempts'] * 2) + ($ipData['targeted_users'] * 1.5), 2),
                    'success_rate' => $totalAttempts > 0 ? round(($ipData['successful_attempts'] / $totalAttempts) * 100, 2) : 0,
                    'latest_attempt' => $ipData['latest_attempt'],
                ];
            })->values()->toArray(),
        ];
    }

    /**
     * Get role analytics using collections for data processing
     */
    public function getRoleAnalytics(Organization $organization): array
    {
        // Get all roles (excluding system roles)
        $roles = DB::table('roles')
            ->where('name', 'NOT LIKE', 'system.%')
            ->select(['id', 'name'])
            ->get()
            ->keyBy('id');

        // Get role-user relationships for this organization
        $roleUsers = DB::table('model_has_roles as mhr')
            ->join('users as u', 'mhr.model_id', '=', 'u.id')
            ->where('mhr.model_type', 'App\\Models\\User')
            ->where('u.organization_id', $organization->id)
            ->whereIn('mhr.role_id', $roles->keys())
            ->select([
                'mhr.role_id',
                'u.id as user_id',
                'u.is_active',
                'u.last_login_at',
            ])
            ->get()
            ->groupBy('role_id');

        // Get role permissions
        $rolePermissions = DB::table('role_has_permissions')
            ->whereIn('role_id', $roles->keys())
            ->select(['role_id', 'permission_id'])
            ->get()
            ->groupBy('role_id');

        return $roles->map(function ($role) use ($roleUsers, $rolePermissions) {
            $usersInRole = collect($roleUsers->get($role->id, []));
            $permissionsInRole = collect($rolePermissions->get($role->id, []));

            // Calculate metrics using collections
            $userCount = $usersInRole->count();
            $permissionCount = $permissionsInRole->count();
            $activeUsers = $usersInRole->where('is_active', true);
            $activeUserRate = $userCount > 0 ? ($activeUsers->count() / $userCount) : 0;
            $latestLogin = $usersInRole->max('last_login_at');

            return [
                'role_name' => $role->name,
                'user_count' => $userCount,
                'permission_count' => $permissionCount,
                'active_user_rate' => round($activeUserRate * 100, 2),
                'latest_user_login' => $latestLogin,
                'utilization_score' => ($userCount * 2) + ($permissionCount * 0.5),
            ];
        })->sortByDesc('user_count')
            ->values()
            ->toArray();
    }

    /**
     * Get comprehensive activity heat map using collections
     */
    public function getActivityHeatMap(Organization $organization, int $days = 7): array
    {
        $startDate = Carbon::now()->subDays($days)->startOfDay();

        // Get successful login logs only
        $logs = DB::table('authentication_logs as al')
            ->join('users as u', 'al.user_id', '=', 'u.id')
            ->where('u.organization_id', $organization->id)
            ->where('al.created_at', '>=', $startDate)
            ->where('al.event', 'login_success')
            ->select([
                'al.created_at',
                'al.user_id',
                'al.application_id',
            ])
            ->get();

        // Process logs using collections to create heat map
        return $logs->groupBy(function ($log) {
            return Carbon::parse($log->created_at)->toDateString();
        })->map(function ($dayLogs) {
            // Group by hour within each day
            return $dayLogs->groupBy(function ($log) {
                return Carbon::parse($log->created_at)->hour;
            })->map(function ($hourLogs) {
                $loginCount = $hourLogs->count();
                $uniqueUsers = $hourLogs->pluck('user_id')->unique()->count();
                $uniqueApps = $hourLogs->pluck('application_id')->unique()->count();

                return [
                    'login_count' => $loginCount,
                    'unique_users' => $uniqueUsers,
                    'unique_apps' => $uniqueApps,
                    'intensity' => min(($loginCount / 10) * 100, 100), // Scale to 0-100
                ];
            })->toArray();
        })->sortByDesc(function ($hourData, $date) {
            return $date; // Sort by date desc
        })->toArray();
    }
}
