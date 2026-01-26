<?php

namespace App\Filament\Pages;

use App\Filament\Widgets\ApplicationAccessMatrix;
use App\Filament\Widgets\AuthStatsOverview;
use App\Filament\Widgets\ErrorTrendsWidget;
use App\Filament\Widgets\LoginActivityChart;
use App\Filament\Widgets\OAuthFlowMonitorWidget;
use App\Filament\Widgets\OrganizationOverviewWidget;
use App\Filament\Widgets\PendingInvitationsWidget;
use App\Filament\Widgets\RealTimeMetricsWidget;
use App\Filament\Widgets\RecentAuthenticationLogs;
use App\Filament\Widgets\SecurityMonitoringWidget;
use App\Filament\Widgets\SystemHealthWidget;
use App\Filament\Widgets\UserActivityWidget;
use App\Filament\Widgets\WebhookActivityChart;
use BackedEnum;
use Filament\Pages\Dashboard as BaseDashboard;

class Dashboard extends BaseDashboard
{
    protected static string|BackedEnum|null $navigationIcon = 'heroicon-o-home';

    protected static ?int $navigationSort = 1;

    public function getWidgets(): array
    {
        return [
            // System Health
            SystemHealthWidget::class,
            AuthStatsOverview::class,
            RealTimeMetricsWidget::class,

            // Security Monitoring
            SecurityMonitoringWidget::class,
            ErrorTrendsWidget::class,

            // Operational Metrics
            LoginActivityChart::class,
            OAuthFlowMonitorWidget::class,
            WebhookActivityChart::class,

            // Organization & Access
            OrganizationOverviewWidget::class,
            UserActivityWidget::class,
            PendingInvitationsWidget::class,
            ApplicationAccessMatrix::class,
            RecentAuthenticationLogs::class,
        ];
    }

    public function getColumns(): int|array
    {
        return [
            'md' => 2,
            'xl' => 4,
        ];
    }

    public function getTitle(): string
    {
        return 'AuthOS Dashboard';
    }

    public function getHeading(): string
    {
        return 'Welcome to AuthOS';
    }

    public function getSubheading(): ?string
    {
        return 'Monitor your authentication service and manage users, applications, and security.';
    }
}
