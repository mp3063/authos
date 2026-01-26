<?php

namespace App\Filament\Widgets;

use App\Services\Monitoring\MetricsCollectionService;
use Filament\Widgets\ChartWidget;

class OAuthFlowMonitorWidget extends ChartWidget
{
    protected ?string $heading = 'OAuth Token Generation (7 Days)';

    protected static ?int $sort = 3;

    protected int|string|array $columnSpan = 'full';

    protected ?string $pollingInterval = '60s';

    protected function getData(): array
    {
        $oauthMetrics = app(MetricsCollectionService::class)->getOAuthMetrics();
        $trend = $oauthMetrics['trend_7_days'];

        $labels = [];
        $data = [];

        foreach ($trend as $day) {
            $labels[] = date('M d', strtotime($day->date));
            $data[] = $day->tokens_created;
        }

        return [
            'datasets' => [
                [
                    'label' => 'Tokens Created',
                    'data' => $data,
                    'borderColor' => '#3b82f6',
                    'backgroundColor' => 'rgba(59, 130, 246, 0.1)',
                ],
            ],
            'labels' => $labels,
        ];
    }

    protected function getType(): string
    {
        return 'line';
    }

    protected function getOptions(): array
    {
        return [
            'plugins' => [
                'legend' => [
                    'display' => true,
                ],
            ],
            'scales' => [
                'y' => [
                    'beginAtZero' => true,
                ],
            ],
        ];
    }
}
