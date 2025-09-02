<?php

namespace App\Services;

use App\Models\Organization;
use App\Models\User;
use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\CustomRole;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;
use Barryvdh\DomPDF\Facade\Pdf;
use Illuminate\Support\Facades\Storage;

class OrganizationReportingService
{
    /**
     * Generate user activity report for an organization
     */
    public function generateUserActivityReport(int $organizationId, array $dateRange = null): array
    {
        $organization = Organization::findOrFail($organizationId);
        
        // Default to last 30 days if no date range provided
        $startDate = isset($dateRange['start']) 
            ? Carbon::parse($dateRange['start'])->startOfDay()
            : Carbon::now()->subDays(30)->startOfDay();
        
        $endDate = isset($dateRange['end'])
            ? Carbon::parse($dateRange['end'])->endOfDay()
            : Carbon::now()->endOfDay();

        // Get organization application IDs
        $applicationIds = $organization->applications()->pluck('id');

        // User statistics
        $totalUsers = User::whereHas('applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })->distinct()->count();

        $activeUsers = User::whereHas('applications', function ($q) use ($applicationIds, $startDate) {
            $q->whereIn('application_id', $applicationIds)
              ->wherePivot('last_login_at', '>=', $startDate);
        })->distinct()->count();

        $newUsers = User::whereHas('applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })->whereBetween('created_at', [$startDate, $endDate])->count();

        $mfaEnabledUsers = User::whereHas('applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })->whereNotNull('mfa_methods')->count();

        // Daily login activity
        $dailyLogins = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where('event', 'login_success')
        ->whereBetween('created_at', [$startDate, $endDate])
        ->select(
            DB::raw("DATE(created_at) as date"),
            DB::raw('COUNT(*) as count'),
            DB::raw('COUNT(DISTINCT user_id) as unique_users')
        )
        ->groupBy('date')
        ->orderBy('date')
        ->get();

        // Top active users
        $topUsers = User::whereHas('applications', function ($q) use ($applicationIds, $startDate) {
            $q->whereIn('application_id', $applicationIds)
              ->wherePivot('last_login_at', '>=', $startDate);
        })
        ->with(['applications' => function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds)
              ->withPivot(['last_login_at', 'login_count']);
        }])
        ->get()
        ->map(function ($user) {
            $totalLogins = $user->applications->sum('pivot.login_count');
            $lastLogin = $user->applications->max('pivot.last_login_at');
            
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'total_logins' => $totalLogins,
                'last_login_at' => $lastLogin,
                'mfa_enabled' => $user->hasMfaEnabled(),
            ];
        })
        ->sortByDesc('total_logins')
        ->take(20)
        ->values();

        // Failed login attempts
        $failedLogins = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where('event', 'login_failed')
        ->whereBetween('created_at', [$startDate, $endDate])
        ->count();

        // Role distribution
        $roleDistribution = User::whereHas('applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->with('roles')
        ->get()
        ->flatMap(function ($user) {
            return $user->roles->pluck('name');
        })
        ->countBy()
        ->map(function ($count, $role) {
            return ['role' => $role, 'count' => $count];
        })
        ->values();

        // Custom role distribution
        $customRoleDistribution = CustomRole::where('organization_id', $organizationId)
            ->withCount('users')
            ->get()
            ->map(function ($role) {
                return [
                    'role' => $role->display_name,
                    'count' => $role->users_count,
                    'permissions' => count($role->permissions ?? []),
                ];
            });

        return [
            'organization' => [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
            ],
            'date_range' => [
                'start' => $startDate->toDateString(),
                'end' => $endDate->toDateString(),
            ],
            'user_statistics' => [
                'total_users' => $totalUsers,
                'active_users' => $activeUsers,
                'new_users' => $newUsers,
                'mfa_enabled_users' => $mfaEnabledUsers,
                'mfa_adoption_rate' => $totalUsers > 0 ? round(($mfaEnabledUsers / $totalUsers) * 100, 2) : 0,
            ],
            'login_statistics' => [
                'total_logins' => $dailyLogins->sum('count'),
                'failed_logins' => $failedLogins,
                'unique_active_users' => $dailyLogins->sum('unique_users'),
                'success_rate' => $dailyLogins->sum('count') + $failedLogins > 0 
                    ? round(($dailyLogins->sum('count') / ($dailyLogins->sum('count') + $failedLogins)) * 100, 2) 
                    : 0,
            ],
            'daily_activity' => $dailyLogins,
            'top_users' => $topUsers,
            'role_distribution' => $roleDistribution,
            'custom_role_distribution' => $customRoleDistribution,
            'generated_at' => Carbon::now()->toISOString(),
        ];
    }

    /**
     * Generate application usage report for an organization
     */
    public function generateApplicationUsageReport(int $organizationId): array
    {
        $organization = Organization::findOrFail($organizationId);

        $applications = $organization->applications()
            ->withCount(['users as total_users'])
            ->with(['users' => function ($q) {
                $q->withPivot(['last_login_at', 'login_count', 'granted_at']);
            }])
            ->get()
            ->map(function ($app) {
                $activeUsers = $app->users->filter(function ($user) {
                    return $user->pivot->last_login_at && 
                           Carbon::parse($user->pivot->last_login_at)->gt(Carbon::now()->subDays(30));
                })->count();

                $totalLogins = $app->users->sum('pivot.login_count');
                $averageLoginsPerUser = $app->total_users > 0 ? round($totalLogins / $app->total_users, 2) : 0;

                // Calculate user engagement score (0-100)
                $engagementScore = 0;
                if ($app->total_users > 0) {
                    $activeUserRate = ($activeUsers / $app->total_users) * 100;
                    $loginFrequency = min($averageLoginsPerUser * 10, 100); // Cap at 100
                    $engagementScore = round(($activeUserRate + $loginFrequency) / 2, 1);
                }

                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'client_id' => $app->client_id,
                    'is_active' => $app->is_active,
                    'created_at' => $app->created_at,
                    'total_users' => $app->total_users,
                    'active_users' => $activeUsers,
                    'total_logins' => $totalLogins,
                    'average_logins_per_user' => $averageLoginsPerUser,
                    'engagement_score' => $engagementScore,
                    'last_activity' => $app->users->max('pivot.last_login_at'),
                    'redirect_uris' => $app->redirect_uris ?? [],
                    'scopes' => $app->scopes ?? [],
                ];
            });

        // Overall statistics
        $totalApplications = $applications->count();
        $activeApplications = $applications->where('is_active', true)->count();
        $totalAppUsers = $applications->sum('total_users');
        $totalAppLogins = $applications->sum('total_logins');
        $averageEngagement = $applications->avg('engagement_score');

        // Token usage statistics
        $tokenStats = DB::table('oauth_access_tokens')
            ->join('oauth_clients', 'oauth_access_tokens.client_id', '=', 'oauth_clients.id')
            ->join('applications', 'oauth_clients.id', '=', 'applications.client_id')
            ->where('applications.organization_id', $organizationId)
            ->select(
                'applications.id as application_id',
                'applications.name as application_name',
                DB::raw('COUNT(*) as total_tokens'),
                DB::raw('COUNT(CASE WHEN oauth_access_tokens.revoked = false THEN 1 END) as active_tokens'),
                DB::raw('COUNT(CASE WHEN oauth_access_tokens.revoked = true THEN 1 END) as revoked_tokens')
            )
            ->groupBy('applications.id', 'applications.name')
            ->get();

        return [
            'organization' => [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
            ],
            'summary' => [
                'total_applications' => $totalApplications,
                'active_applications' => $activeApplications,
                'total_users_across_apps' => $totalAppUsers,
                'total_logins_across_apps' => $totalAppLogins,
                'average_engagement_score' => round($averageEngagement, 1),
            ],
            'applications' => $applications,
            'token_statistics' => $tokenStats,
            'generated_at' => Carbon::now()->toISOString(),
        ];
    }

    /**
     * Generate security audit report for an organization
     */
    public function generateSecurityAuditReport(int $organizationId): array
    {
        $organization = Organization::findOrFail($organizationId);
        $applicationIds = $organization->applications()->pluck('id');

        // Security events from the last 90 days
        $startDate = Carbon::now()->subDays(90);

        // Failed login attempts
        $failedLogins = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where('event', 'login_failed')
        ->where('created_at', '>=', $startDate)
        ->select(
            DB::raw("DATE(created_at) as date"),
            DB::raw('COUNT(*) as count'),
            DB::raw('COUNT(DISTINCT ip_address) as unique_ips'),
            DB::raw('COUNT(DISTINCT user_id) as affected_users')
        )
        ->groupBy('date')
        ->orderBy('date')
        ->get();

        // Suspicious IP addresses (multiple failed logins)
        $suspiciousIPs = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where('event', 'login_failed')
        ->where('created_at', '>=', $startDate)
        ->select(
            'ip_address',
            DB::raw('COUNT(*) as failed_attempts'),
            DB::raw('COUNT(DISTINCT user_id) as affected_users'),
            DB::raw('MAX(created_at) as last_attempt')
        )
        ->groupBy('ip_address')
        ->having('failed_attempts', '>=', 10)
        ->orderByDesc('failed_attempts')
        ->get();

        // Users without MFA
        $usersWithoutMFA = User::whereHas('applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where(function ($q) {
            $q->whereNull('mfa_methods')->orWhere('mfa_methods', '[]');
        })
        ->select('id', 'name', 'email', 'created_at')
        ->get();

        // Privileged users (admins, owners)
        $privilegedUsers = User::whereHas('applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->whereHas('roles', function ($q) {
            $q->whereIn('name', ['Super Admin', 'Organization Admin', 'Organization Owner']);
        })
        ->with('roles')
        ->select('id', 'name', 'email', 'created_at')
        ->get()
        ->map(function ($user) {
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'roles' => $user->roles->pluck('name'),
                'mfa_enabled' => $user->hasMfaEnabled(),
                'created_at' => $user->created_at,
            ];
        });

        // Token revocation events
        $tokenRevocations = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where('event', 'token_revoked')
        ->where('created_at', '>=', $startDate)
        ->count();

        // Password change events
        $passwordChanges = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->where('event', 'password_changed')
        ->where('created_at', '>=', $startDate)
        ->count();

        // Organization security settings compliance
        $orgSettings = $organization->settings ?? [];
        $securityCompliance = [
            'mfa_required' => $orgSettings['require_mfa'] ?? false,
            'password_policy_enforced' => isset($orgSettings['password_policy']),
            'session_timeout_configured' => isset($orgSettings['session_timeout']),
            'allowed_domains_configured' => !empty($orgSettings['allowed_domains'] ?? []),
        ];

        $complianceScore = (array_sum($securityCompliance) / count($securityCompliance)) * 100;

        // Recent security events (last 30 days)
        $recentSecurityEvents = AuthenticationLog::whereHas('user.applications', function ($q) use ($applicationIds) {
            $q->whereIn('application_id', $applicationIds);
        })
        ->whereIn('event', ['login_failed', 'token_revoked', 'mfa_failed', 'password_changed'])
        ->where('created_at', '>=', Carbon::now()->subDays(30))
        ->with('user:id,name,email')
        ->orderByDesc('created_at')
        ->limit(100)
        ->get()
        ->map(function ($log) {
            return [
                'event' => $log->event,
                'user' => $log->user ? [
                    'id' => $log->user->id,
                    'name' => $log->user->name,
                    'email' => $log->user->email,
                ] : null,
                'ip_address' => $log->ip_address,
                'user_agent' => $log->user_agent,
                'success' => $log->success,
                'metadata' => $log->metadata,
                'created_at' => $log->created_at,
            ];
        });

        return [
            'organization' => [
                'id' => $organization->id,
                'name' => $organization->name,
                'slug' => $organization->slug,
            ],
            'audit_period' => [
                'start' => $startDate->toDateString(),
                'end' => Carbon::now()->toDateString(),
            ],
            'security_summary' => [
                'total_failed_logins' => $failedLogins->sum('count'),
                'suspicious_ips' => $suspiciousIPs->count(),
                'users_without_mfa' => $usersWithoutMFA->count(),
                'privileged_users' => $privilegedUsers->count(),
                'token_revocations' => $tokenRevocations,
                'password_changes' => $passwordChanges,
                'compliance_score' => round($complianceScore, 1),
            ],
            'failed_login_trends' => $failedLogins,
            'suspicious_ip_addresses' => $suspiciousIPs,
            'users_without_mfa' => $usersWithoutMFA->map(function ($user) {
                return [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'account_age_days' => Carbon::now()->diffInDays($user->created_at),
                ];
            }),
            'privileged_users' => $privilegedUsers,
            'security_compliance' => $securityCompliance,
            'recent_security_events' => $recentSecurityEvents,
            'recommendations' => $this->generateSecurityRecommendations($organization, $usersWithoutMFA->count(), $suspiciousIPs->count(), $complianceScore),
            'generated_at' => Carbon::now()->toISOString(),
        ];
    }

    /**
     * Export report to PDF format
     */
    public function exportReportToPDF(array $report, string $reportType): string
    {
        $organization = $report['organization'];
        $filename = sprintf(
            '%s_%s_report_%s.pdf',
            $organization['slug'],
            $reportType,
            Carbon::now()->format('Y-m-d_H-i-s')
        );

        // Generate PDF using DOMPDF
        $pdf = PDF::loadView("reports.{$reportType}", compact('report'));
        $pdf->setPaper('a4', 'portrait');
        
        $exportPath = 'reports/' . $filename;
        Storage::put($exportPath, $pdf->output());

        return $exportPath;
    }

    /**
     * Generate security recommendations based on audit findings
     */
    private function generateSecurityRecommendations(Organization $organization, int $usersWithoutMFA, int $suspiciousIPs, float $complianceScore): array
    {
        $recommendations = [];

        if ($usersWithoutMFA > 0) {
            $recommendations[] = [
                'priority' => 'high',
                'category' => 'mfa',
                'title' => 'Enable Multi-Factor Authentication',
                'description' => "There are {$usersWithoutMFA} users without MFA enabled. Consider enforcing MFA organization-wide.",
                'action' => 'Enable organization-wide MFA requirement in settings.',
            ];
        }

        if ($suspiciousIPs > 0) {
            $recommendations[] = [
                'priority' => 'high',
                'category' => 'security',
                'title' => 'Investigate Suspicious IP Addresses',
                'description' => "Detected {$suspiciousIPs} IP addresses with multiple failed login attempts.",
                'action' => 'Review suspicious IPs and consider implementing IP allowlists.',
            ];
        }

        if ($complianceScore < 75) {
            $recommendations[] = [
                'priority' => 'medium',
                'category' => 'compliance',
                'title' => 'Improve Security Compliance',
                'description' => "Current compliance score is {$complianceScore}%. Review security settings.",
                'action' => 'Configure password policies, session timeouts, and domain restrictions.',
            ];
        }

        $orgSettings = $organization->settings ?? [];
        if (!($orgSettings['require_mfa'] ?? false)) {
            $recommendations[] = [
                'priority' => 'high',
                'category' => 'mfa',
                'title' => 'Require MFA for All Users',
                'description' => 'MFA is not currently required organization-wide.',
                'action' => 'Enable MFA requirement in organization security settings.',
            ];
        }

        if (empty($orgSettings['allowed_domains'] ?? [])) {
            $recommendations[] = [
                'priority' => 'medium',
                'category' => 'access_control',
                'title' => 'Configure Domain Restrictions',
                'description' => 'No domain restrictions are configured for user registration.',
                'action' => 'Set allowed email domains to restrict user registration.',
            ];
        }

        return $recommendations;
    }
}