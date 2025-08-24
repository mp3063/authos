<?php

namespace App\Filament\Pages;

use App\Filament\Widgets\AuthStatsOverview;
use App\Filament\Widgets\LoginActivityChart;
use App\Filament\Widgets\RecentAuthenticationLogs;
use Filament\Pages\Dashboard as BaseDashboard;

class Dashboard extends BaseDashboard
{
    protected static string|null|\BackedEnum $navigationIcon = 'heroicon-o-home';

    protected static ?int $navigationSort = 1;

    public function getWidgets(): array
    {
        return [
            AuthStatsOverview::class,
            LoginActivityChart::class,
            RecentAuthenticationLogs::class,
        ];
    }

    public function getColumns(): int | array
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