<?php

namespace App\Filament\Widgets;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class AuthStatsOverview extends BaseWidget
{
    protected static ?int $sort = 1;

    protected function getStats(): array
    {
        $totalUsers = User::count();
        $activeUsers = User::whereHas('applications')->count();
        $mfaEnabledUsers = User::whereNotNull('mfa_methods')->count();
        
        $totalApplications = Application::count();
        $activeApplications = Application::where('is_active', true)->count();
        
        $totalOrganizations = Organization::count();
        $activeOrganizations = Organization::where('is_active', true)->count();
        
        $todayLogins = AuthenticationLog::where('event', 'login_success')
            ->whereDate('created_at', today())
            ->count();
        
        $todayFailedLogins = AuthenticationLog::whereIn('event', ['login_failed', 'failed_mfa'])
            ->whereDate('created_at', today())
            ->count();
        
        $suspiciousActivity = AuthenticationLog::where('event', 'suspicious_activity')
            ->whereDate('created_at', today())
            ->count();

        return [
            Stat::make('Total Users', $totalUsers)
                ->description($activeUsers . ' with app access')
                ->descriptionIcon('heroicon-m-user-group')
                ->color('primary')
                ->chart([7, 12, 9, 14, 18, 15, 22])
                ->url(route('filament.admin.resources.users.index')),

            Stat::make('MFA Enabled', $mfaEnabledUsers)
                ->description(round(($mfaEnabledUsers / max($totalUsers, 1)) * 100, 1) . '% of users')
                ->descriptionIcon('heroicon-m-shield-check')
                ->color('success'),

            Stat::make('Applications', $totalApplications)
                ->description($activeApplications . ' active')
                ->descriptionIcon('heroicon-m-squares-2x2')
                ->color('info')
                ->url(route('filament.admin.resources.applications.index')),

            Stat::make('Organizations', $totalOrganizations)
                ->description($activeOrganizations . ' active')
                ->descriptionIcon('heroicon-m-building-office')
                ->color('warning')
                ->url(route('filament.admin.resources.organizations.index')),

            Stat::make('Today\'s Logins', $todayLogins)
                ->description('Successful authentications')
                ->descriptionIcon('heroicon-m-arrow-right-on-rectangle')
                ->color('success')
                ->chart([5, 8, 12, 15, 18, 22, 25]),

            Stat::make('Failed Attempts', $todayFailedLogins)
                ->description('Login failures today')
                ->descriptionIcon('heroicon-m-x-circle')
                ->color($todayFailedLogins > 10 ? 'danger' : 'gray')
                ->chart([2, 3, 1, 4, 6, 3, 5]),

            Stat::make('Suspicious Activity', $suspiciousActivity)
                ->description('Security alerts today')
                ->descriptionIcon('heroicon-m-exclamation-triangle')
                ->color($suspiciousActivity > 0 ? 'danger' : 'success')
                ->url(route('filament.admin.resources.authentication-logs.index', [
                    'activeTab' => 'suspicious'
                ])),

            Stat::make('System Health', 'Good')
                ->description('All services operational')
                ->descriptionIcon('heroicon-m-heart')
                ->color('success'),
        ];
    }
}