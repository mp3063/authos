<?php

namespace App\Filament\Widgets;

use App\Enums\WebhookDeliveryStatus;
use App\Filament\Concerns\ScopesToOrganization;
use App\Models\WebhookDelivery;
use Filament\Facades\Filament;
use Filament\Widgets\ChartWidget;
use Illuminate\Support\Carbon;

class WebhookActivityChart extends ChartWidget
{
    use ScopesToOrganization;

    protected ?string $heading = 'Webhook Deliveries (Last 7 Days)';

    protected static ?int $sort = 3;

    protected int|string|array $columnSpan = 'full';

    protected function getData(): array
    {
        $data = [];
        $labels = [];

        // Get last 7 days of data
        for ($i = 6; $i >= 0; $i--) {
            $date = Carbon::today()->subDays($i);
            $labels[] = $date->format('M j');

            $query = static::scopeToOrganizationThrough(WebhookDelivery::query(), 'webhook')
                ->whereDate('created_at', $date);

            $successful = (clone $query)->where('status', WebhookDeliveryStatus::SUCCESS)->count();
            $failed = (clone $query)->where('status', WebhookDeliveryStatus::FAILED)->count();
            $retrying = (clone $query)->where('status', WebhookDeliveryStatus::RETRYING)->count();

            $data['successful'][] = $successful;
            $data['failed'][] = $failed;
            $data['retrying'][] = $retrying;
        }

        return [
            'datasets' => [
                [
                    'label' => 'Successful',
                    'data' => $data['successful'],
                    'backgroundColor' => 'rgba(34, 197, 94, 0.2)',
                    'borderColor' => 'rgb(34, 197, 94)',
                    'borderWidth' => 2,
                    'fill' => true,
                ],
                [
                    'label' => 'Failed',
                    'data' => $data['failed'],
                    'backgroundColor' => 'rgba(239, 68, 68, 0.2)',
                    'borderColor' => 'rgb(239, 68, 68)',
                    'borderWidth' => 2,
                    'fill' => true,
                ],
                [
                    'label' => 'Retrying',
                    'data' => $data['retrying'],
                    'backgroundColor' => 'rgba(234, 179, 8, 0.2)',
                    'borderColor' => 'rgb(234, 179, 8)',
                    'borderWidth' => 2,
                    'fill' => true,
                ],
            ],
            'labels' => $labels,
        ];
    }

    public static function canView(): bool
    {
        return Filament::auth()->user()?->hasOrganizationPermission('webhooks.read') === true;
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
                    'ticks' => [
                        'precision' => 0,
                    ],
                ],
            ],
            'plugins' => [
                'legend' => [
                    'display' => true,
                    'position' => 'top',
                ],
                'tooltip' => [
                    'mode' => 'index',
                    'intersect' => false,
                ],
            ],
            'interaction' => [
                'mode' => 'nearest',
                'intersect' => false,
            ],
            'elements' => [
                'point' => [
                    'radius' => 4,
                    'hoverRadius' => 6,
                ],
                'line' => [
                    'tension' => 0.3,
                ],
            ],
        ];
    }
}
