<?php

namespace App\Filament\Widgets;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Invitation;
use App\Models\User;
use Filament\Facades\Filament;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;
use Illuminate\Support\Facades\Cache;

class OrganizationOverviewWidget extends BaseWidget
{
    protected static ?int $sort = 1;

    protected static bool $isLazy = false;

    protected function getStats(): array
    {
        $user = Filament::auth()->user();
        
        // Only show for organization owners/admins
        if (!$user->isOrganizationOwner() && !$user->isOrganizationAdmin()) {
            return [];
        }

        $organizationId = $user->organization_id;
        $cacheKey = "org_overview_stats_{$organizationId}";

        return Cache::remember($cacheKey, 300, function () use ($organizationId, $user) {
            // Get organization users (users who have access to any app in this org)
            $totalUsers = User::whereHas('applications', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })->count();

            // Get active users (logged in within last 30 days)
            $activeUsers = User::whereHas('applications', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })->whereHas('authenticationLogs', function ($query) {
                $query->where('event', 'login')
                    ->where('created_at', '>=', now()->subDays(30));
            })->count();

            // Get organization applications
            $totalApplications = Application::where('organization_id', $organizationId)->count();
            $activeApplications = Application::where('organization_id', $organizationId)
                ->where('is_active', true)
                ->count();

            // Get pending invitations
            $pendingInvitations = Invitation::where('organization_id', $organizationId)
                ->pending()
                ->count();

            // Get today's activities
            $todayLogins = AuthenticationLog::whereHas('application', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })->where('event', 'login')
                ->whereDate('created_at', today())
                ->count();

            // Get failed login attempts today
            $todayFailedLogins = AuthenticationLog::whereHas('application', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })->whereIn('event', ['failed_login', 'failed_mfa'])
                ->whereDate('created_at', today())
                ->count();

            // MFA adoption rate
            $mfaEnabledUsers = User::whereHas('applications', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })->whereNotNull('mfa_methods')->count();

            $mfaRate = $totalUsers > 0 ? round(($mfaEnabledUsers / $totalUsers) * 100, 1) : 0;

            // Get last 7 days login trend for chart
            $loginTrend = [];
            for ($i = 6; $i >= 0; $i--) {
                $date = now()->subDays($i);
                $count = AuthenticationLog::whereHas('application', function ($query) use ($organizationId) {
                    $query->where('organization_id', $organizationId);
                })->where('event', 'login')
                    ->whereDate('created_at', $date)
                    ->count();
                $loginTrend[] = $count;
            }

            return [
                Stat::make('Total Users', $totalUsers)
                    ->description($activeUsers . ' active in last 30 days')
                    ->descriptionIcon('heroicon-m-user-group')
                    ->color('primary')
                    ->chart($loginTrend),

                Stat::make('Applications', $totalApplications)
                    ->description($activeApplications . ' active')
                    ->descriptionIcon('heroicon-m-squares-2x2')
                    ->color('info')
                    ->url(fn() => $user->can('view applications') ? 
                        route('filament.admin.resources.applications.index', [
                            'organization' => $user->organization->slug
                        ]) : null),

                Stat::make('Pending Invitations', $pendingInvitations)
                    ->description('Awaiting acceptance')
                    ->descriptionIcon('heroicon-m-envelope')
                    ->color($pendingInvitations > 0 ? 'warning' : 'success')
                    ->url(fn() => $user->can('view invitations') ? '#pending-invitations' : null),

                Stat::make('MFA Adoption', $mfaRate . '%')
                    ->description($mfaEnabledUsers . ' of ' . $totalUsers . ' users')
                    ->descriptionIcon('heroicon-m-shield-check')
                    ->color($mfaRate >= 80 ? 'success' : ($mfaRate >= 50 ? 'warning' : 'danger')),

                Stat::make('Today\'s Logins', $todayLogins)
                    ->description('Successful authentications')
                    ->descriptionIcon('heroicon-m-arrow-right-on-rectangle')
                    ->color('success')
                    ->chart(array_slice($loginTrend, -3)), // Last 3 days mini chart

                Stat::make('Failed Attempts', $todayFailedLogins)
                    ->description('Login failures today')
                    ->descriptionIcon('heroicon-m-x-circle')
                    ->color($todayFailedLogins > 5 ? 'danger' : 'gray'),

                Stat::make('Security Score', $this->calculateSecurityScore($mfaRate, $todayFailedLogins, $totalUsers))
                    ->description('Organization security rating')
                    ->descriptionIcon('heroicon-m-shield-exclamation')
                    ->color($this->getSecurityScoreColor($this->calculateSecurityScore($mfaRate, $todayFailedLogins, $totalUsers))),

                Stat::make('System Status', 'Operational')
                    ->description('All services running')
                    ->descriptionIcon('heroicon-m-check-circle')
                    ->color('success'),
            ];
        });
    }

    protected function calculateSecurityScore(float $mfaRate, int $failedLogins, int $totalUsers): string
    {
        $score = 100;
        
        // Deduct points for low MFA adoption
        if ($mfaRate < 50) {
            $score -= 30;
        } elseif ($mfaRate < 80) {
            $score -= 15;
        }
        
        // Deduct points for failed login attempts
        if ($failedLogins > 10) {
            $score -= 20;
        } elseif ($failedLogins > 5) {
            $score -= 10;
        }
        
        // Bonus for high user engagement
        if ($totalUsers > 50) {
            $score += 5;
        }
        
        return max(0, min(100, $score)) . '/100';
    }

    protected function getSecurityScoreColor(string $score): string
    {
        $numericScore = (int) explode('/', $score)[0];
        
        if ($numericScore >= 90) {
            return 'success';
        } elseif ($numericScore >= 70) {
            return 'warning';
        } else {
            return 'danger';
        }
    }

    public function getColumns(): int
    {
        return 2; // Two columns layout for better organization
    }

    protected ?string $pollingInterval = '60s'; // Refresh every minute
}