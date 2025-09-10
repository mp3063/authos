<?php

namespace App\Services\Database;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Collection as BaseCollection;

/**
 * Laravel-native optimized query service using proper Eloquent patterns
 */
class OptimizedQueryService
{
    /**
     * Get user analytics with proper eager loading to avoid N+1
     */
    public function getUserAnalytics(Organization $organization, array $filters = []): array
    {
        $startDate = isset($filters['start_date'])
            ? Carbon::parse($filters['start_date'])->startOfDay()
            : now()->subDays(30)->startOfDay();

        // Get users with all needed relationships in one query
        $users = $organization->users()
            ->with([
                'roles:id,name',
                'applications' => function ($query) {
                    $query->select('applications.id', 'applications.name')
                        ->withPivot(['granted_at', 'last_login_at', 'login_count']);
                },
                'authenticationLogs' => function ($query) use ($startDate) {
                    $query->where('created_at', '>=', $startDate)
                        ->select('id', 'user_id', 'event', 'created_at');
                },
            ])
            ->get();

        // Use Laravel collections to process data efficiently
        $analytics = [
            'total_users' => $users->count(),
            'active_users' => $users->where('is_active', true)->count(),
            'new_users' => $users->where('created_at', '>=', $startDate)->count(),
            'mfa_enabled_users' => $users->whereNotNull('mfa_methods')->count(),
            'users_with_apps' => $users->filter(fn ($user) => $user->applications->count() > 0)->count(),
            'total_login_count' => $users->sum(fn ($user) => $user->applications->sum('pivot.login_count')),
            'recent_auth_events' => $users->sum(fn ($user) => $user->authenticationLogs->count()),
        ];

        return $analytics;
    }

    /**
     * Get application usage data with optimized relationships
     */
    public function getApplicationUsage(Organization $organization, int $days = 30): BaseCollection
    {
        $startDate = now()->subDays($days)->startOfDay();

        return $organization->applications()
            ->with([
                'users' => function ($query) use ($startDate) {
                    $query->wherePivot('last_login_at', '>=', $startDate)
                        ->withPivot(['last_login_at', 'login_count']);
                },
                'authenticationLogs' => function ($query) use ($startDate) {
                    $query->where('created_at', '>=', $startDate)
                        ->select('id', 'application_id', 'event', 'user_id');
                },
            ])
            ->get()
            ->map(function ($app) {
                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'is_active' => $app->is_active,
                    'total_users' => $app->users->count(),
                    'active_users' => $app->users->filter(fn ($u) => $u->pivot->last_login_at)->count(),
                    'total_logins' => $app->users->sum('pivot.login_count'),
                    'recent_events' => $app->authenticationLogs->count(),
                    'success_events' => $app->authenticationLogs->where('event', 'login_success')->count(),
                    'failed_events' => $app->authenticationLogs->where('event', 'login_failed')->count(),
                ];
            });
    }

    /**
     * Get authentication trends using Laravel collections
     */
    public function getAuthenticationTrends(Organization $organization, int $days = 7): BaseCollection
    {
        $startDate = now()->subDays($days)->startOfDay();

        // Get all authentication logs for the period with user relationship
        $authLogs = AuthenticationLog::with(['user' => function ($query) use ($organization) {
            $query->where('organization_id', $organization->id);
        }])
            ->whereHas('user', function ($query) use ($organization) {
                $query->where('organization_id', $organization->id);
            })
            ->where('created_at', '>=', $startDate)
            ->get();

        // Group by date and process with collections
        return $authLogs
            ->groupBy(function ($log) {
                return $log->created_at->format('Y-m-d');
            })
            ->map(function ($dayLogs, $date) {
                $successfulLogins = $dayLogs->where('event', 'login_success')->count();
                $failedLogins = $dayLogs->where('event', 'login_failed')->count();
                $totalAttempts = $successfulLogins + $failedLogins;

                return [
                    'date' => $date,
                    'successful_logins' => $successfulLogins,
                    'failed_logins' => $failedLogins,
                    'unique_users' => $dayLogs->unique('user_id')->count(),
                    'unique_ips' => $dayLogs->unique('ip_address')->count(),
                    'success_rate' => $totalAttempts > 0 ? round(($successfulLogins / $totalAttempts) * 100, 2) : 0,
                ];
            })
            ->sortKeys()
            ->values();
    }

    /**
     * Get top active users efficiently
     */
    public function getTopActiveUsers(Organization $organization, int $limit = 20): BaseCollection
    {
        return $organization->users()
            ->with(['applications' => function ($query) {
                $query->withPivot(['last_login_at', 'login_count']);
            }])
            ->get()
            ->map(function ($user) {
                $totalLogins = $user->applications->sum('pivot.login_count');
                $latestLogin = $user->applications->max('pivot.last_login_at');

                return [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'is_active' => $user->is_active,
                    'total_logins' => $totalLogins,
                    'latest_login' => $latestLogin,
                    'app_count' => $user->applications->count(),
                    'mfa_enabled' => ! empty($user->mfa_methods),
                ];
            })
            ->sortByDesc('total_logins')
            ->take($limit)
            ->values();
    }

    /**
     * Get security insights using relationships
     */
    public function getSecurityInsights(Organization $organization, int $days = 7): array
    {
        $startDate = now()->subDays($days)->startOfDay();

        // Get failed login attempts
        $failedLogins = AuthenticationLog::with(['user' => function ($query) use ($organization) {
            $query->where('organization_id', $organization->id);
        }])
            ->whereHas('user', function ($query) use ($organization) {
                $query->where('organization_id', $organization->id);
            })
            ->where('event', 'login_failed')
            ->where('created_at', '>=', $startDate)
            ->get();

        // Process suspicious IPs using collections
        $suspiciousIps = $failedLogins
            ->groupBy('ip_address')
            ->filter(function ($attempts) {
                return $attempts->count() >= 3; // 3+ failed attempts
            })
            ->map(function ($attempts, $ip) {
                return [
                    'ip_address' => $ip,
                    'failed_attempts' => $attempts->count(),
                    'unique_targets' => $attempts->unique('user_id')->count(),
                    'latest_attempt' => $attempts->max('created_at'),
                    'risk_score' => $attempts->count() * 1.5 + ($attempts->unique('user_id')->count() * 0.5),
                ];
            })
            ->sortByDesc('risk_score')
            ->take(10)
            ->values();

        return [
            'period_days' => $days,
            'total_failed_attempts' => $failedLogins->count(),
            'unique_failed_ips' => $failedLogins->unique('ip_address')->count(),
            'unique_targeted_users' => $failedLogins->unique('user_id')->count(),
            'suspicious_ips' => $suspiciousIps->toArray(),
            'high_risk_ips' => $suspiciousIps->where('risk_score', '>', 10)->count(),
        ];
    }

    /**
     * Get user behavior analysis
     */
    public function analyzeUserBehavior(Organization $organization, int $days = 30): BaseCollection
    {
        $startDate = now()->subDays($days)->startOfDay();

        return $organization->users()
            ->with([
                'authenticationLogs' => function ($query) use ($startDate) {
                    $query->where('created_at', '>=', $startDate);
                },
            ])
            ->get()
            ->filter(function ($user) {
                return $user->authenticationLogs->count() > 0;
            })
            ->map(function ($user) {
                $logs = $user->authenticationLogs;
                $uniqueIps = $logs->unique('ip_address')->count();
                $failedAttempts = $logs->where('event', 'login_failed')->count();
                $successfulLogins = $logs->where('event', 'login_success')->count();

                $anomalyScore = 0;
                $anomalies = [];

                // Check for anomalies
                if ($uniqueIps > 5) {
                    $anomalyScore += 2;
                    $anomalies[] = 'multiple_locations';
                }
                if ($failedAttempts > 10) {
                    $anomalyScore += 3;
                    $anomalies[] = 'excessive_failures';
                }
                if ($logs->unique('user_agent')->count() > 3) {
                    $anomalyScore += 1;
                    $anomalies[] = 'multiple_devices';
                }

                return [
                    'user_id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'unique_ips' => $uniqueIps,
                    'failed_attempts' => $failedAttempts,
                    'successful_logins' => $successfulLogins,
                    'total_events' => $logs->count(),
                    'anomaly_score' => $anomalyScore,
                    'anomalies' => $anomalies,
                    'risk_level' => $anomalyScore >= 4 ? 'high' : ($anomalyScore >= 2 ? 'medium' : 'low'),
                ];
            })
            ->filter(function ($analysis) {
                return $analysis['anomaly_score'] > 0; // Only return users with anomalies
            })
            ->sortByDesc('anomaly_score')
            ->values();
    }

    /**
     * Get invitation analytics
     */
    public function getInvitationAnalytics(Organization $organization): array
    {
        $invitations = $organization->invitations()
            ->with(['inviter:id,name', 'acceptor:id,name'])
            ->get();

        return [
            'total_invitations' => $invitations->count(),
            'pending' => $invitations->where('status', 'pending')->count(),
            'accepted' => $invitations->where('status', 'accepted')->count(),
            'expired' => $invitations->where('status', 'expired')->count(),
            'acceptance_rate' => $invitations->count() > 0
                ? round(($invitations->where('status', 'accepted')->count() / $invitations->count()) * 100, 2)
                : 0,
            'recent_invitations' => $invitations
                ->where('created_at', '>=', now()->subDays(7))
                ->count(),
            'top_inviters' => $invitations
                ->groupBy('inviter_id')
                ->map(function ($userInvitations) {
                    $first = $userInvitations->first();

                    return [
                        'user_id' => $first->inviter_id,
                        'name' => $first->inviter->name ?? 'Unknown',
                        'invitation_count' => $userInvitations->count(),
                        'accepted_count' => $userInvitations->where('status', 'accepted')->count(),
                    ];
                })
                ->sortByDesc('invitation_count')
                ->take(10)
                ->values()
                ->toArray(),
        ];
    }

    /**
     * Get role distribution analysis
     */
    public function getRoleDistribution(Organization $organization): BaseCollection
    {
        return $organization->users()
            ->with(['roles:id,name'])
            ->get()
            ->flatMap(function ($user) {
                return $user->roles->pluck('name');
            })
            ->countBy()
            ->map(function ($count, $roleName) {
                return [
                    'role_name' => $roleName,
                    'user_count' => $count,
                ];
            })
            ->sortByDesc('user_count')
            ->values();
    }
}
