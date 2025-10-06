<?php

namespace App\Filament\Widgets;

use App\Services\Monitoring\ErrorTrackingService;
use Filament\Widgets\ChartWidget;

class ErrorTrendsWidget extends ChartWidget
{
    protected ?string $heading = 'Error Trends (7 Days)';

    protected static ?int $sort = 5;

    protected int|string|array $columnSpan = 'full';

    protected ?string $pollingInterval = '60s';

    public function __construct(
        private readonly ErrorTrackingService $errorTrackingService
    ) {
        parent::__construct();
    }

    protected function getData(): array
    {
        $trends = $this->errorTrackingService->getErrorTrends(7);

        $labels = [];
        $criticalData = [];
        $errorData = [];
        $warningData = [];

        foreach ($trends as $trend) {
            $labels[] = date('M d', strtotime($trend['date']));
            $criticalData[] = $trend['critical'];
            $errorData[] = $trend['error'];
            $warningData[] = $trend['warning'];
        }

        return [
            'datasets' => [
                [
                    'label' => 'Critical',
                    'data' => $criticalData,
                    'borderColor' => '#ef4444',
                    'backgroundColor' => 'rgba(239, 68, 68, 0.1)',
                ],
                [
                    'label' => 'Errors',
                    'data' => $errorData,
                    'borderColor' => '#f59e0b',
                    'backgroundColor' => 'rgba(245, 158, 11, 0.1)',
                ],
                [
                    'label' => 'Warnings',
                    'data' => $warningData,
                    'borderColor' => '#eab308',
                    'backgroundColor' => 'rgba(234, 179, 8, 0.1)',
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
                    'stacked' => false,
                ],
            ],
        ];
    }
}
