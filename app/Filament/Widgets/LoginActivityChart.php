<?php

namespace App\Filament\Widgets;

use App\Filament\Concerns\ScopesToOrganization;
use App\Models\AuthenticationLog;
use Filament\Facades\Filament;
use Filament\Widgets\ChartWidget;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;

class LoginActivityChart extends ChartWidget
{
    use ScopesToOrganization;

    // protected ?string $heading = 'Login Activity (Last 7 Days)';

    protected static ?int $sort = 2;

    protected int|string|array $columnSpan = 'full';

    protected function getData(): array
    {
        $data = [];
        $labels = [];

        // Get last 7 days of data
        for ($i = 6; $i >= 0; $i--) {
            $date = Carbon::today()->subDays($i);
            $labels[] = $date->format('M j');

            $logins = $this->logs()->where('event', 'login_success')
                ->whereDate('created_at', $date)
                ->count();

            $failures = $this->logs()->whereIn('event', ['login_failed', 'failed_mfa'])
                ->whereDate('created_at', $date)
                ->count();

            $data['successful'][] = $logins;
            $data['failed'][] = $failures;
        }

        return [
            'datasets' => [
                [
                    'label' => 'Successful Logins',
                    'data' => $data['successful'],
                    'backgroundColor' => 'rgba(34, 197, 94, 0.2)',
                    'borderColor' => 'rgb(34, 197, 94)',
                    'borderWidth' => 2,
                    'fill' => true,
                ],
                [
                    'label' => 'Failed Attempts',
                    'data' => $data['failed'],
                    'backgroundColor' => 'rgba(239, 68, 68, 0.2)',
                    'borderColor' => 'rgb(239, 68, 68)',
                    'borderWidth' => 2,
                    'fill' => true,
                ],
            ],
            'labels' => $labels,
        ];
    }

    public static function canView(): bool
    {
        return Filament::auth()->user()?->hasOrganizationPermission('auth_logs.read') === true;
    }

    private function logs(): Builder
    {
        return static::scopeToOrganizationThrough(AuthenticationLog::query(), 'user');
    }

    protected function getType(): string
    {
        return 'line';
    }

    protected function getOptions(): array
    {
        return [
            'scales' => [
                'y' => [
                    'beginAtZero' => true,
                ],
            ],
            'plugins' => [
                'legend' => [
                    'display' => true,
                    'position' => 'top',
                ],
            ],
            'interaction' => [
                'intersect' => false,
            ],
            'elements' => [
                'point' => [
                    'radius' => 4,
                ],
            ],
        ];
    }
}
