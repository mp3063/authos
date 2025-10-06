<?php

namespace App\Filament\Widgets;

use App\Services\Monitoring\MetricsCollectionService;
use Filament\Widgets\StatsOverviewWidget as BaseWidget;
use Filament\Widgets\StatsOverviewWidget\Stat;

class RealTimeMetricsWidget extends BaseWidget
{
    protected static ?int $sort = 2;

    protected int|string|array $columnSpan = 'full';

    // Auto-refresh every 30 seconds
    protected ?string $pollingInterval = '30s';

    public function __construct(
        private readonly MetricsCollectionService $metricsService
    ) {
        parent::__construct();
    }

    protected function getStats(): array
    {
        $apiMetrics = $this->metricsService->getApiMetrics();
        $authMetrics = $this->metricsService->getAuthenticationMetrics();
        $webhookMetrics = $this->metricsService->getWebhookMetrics();
        $performanceMetrics = $this->metricsService->getPerformanceMetrics();

        return [
            Stat::make('API Requests (Today)', number_format($apiMetrics['total_requests']))
                ->description('Error rate: '.$apiMetrics['error_rate'].'%')
                ->descriptionIcon('heroicon-m-arrow-trending-up')
                ->color($apiMetrics['error_rate'] > 5 ? 'danger' : 'success'),

            Stat::make('Avg Response Time', round($apiMetrics['avg_response_time_ms'], 2).' ms')
                ->description('Max: '.round($apiMetrics['max_response_time_ms'], 2).' ms')
                ->descriptionIcon('heroicon-m-clock')
                ->color($apiMetrics['avg_response_time_ms'] > 100 ? 'warning' : 'success'),

            Stat::make('Authentication Success Rate', $authMetrics['today']['success_rate'].'%')
                ->description($authMetrics['today']['successful'].' / '.$authMetrics['today']['total_attempts'])
                ->descriptionIcon('heroicon-m-lock-closed')
                ->color($authMetrics['today']['success_rate'] < 90 ? 'danger' : 'success'),

            Stat::make('Webhook Success Rate', $webhookMetrics['success_rate'].'%')
                ->description($webhookMetrics['deliveries_today'].' deliveries today')
                ->descriptionIcon('heroicon-m-bell')
                ->color($webhookMetrics['success_rate'] < 95 ? 'warning' : 'success'),

            Stat::make('Cache Hit Rate', $performanceMetrics['cache']['hit_rate'].'%')
                ->description($performanceMetrics['cache']['hits'].' hits')
                ->descriptionIcon('heroicon-m-circle-stack')
                ->color($performanceMetrics['cache']['hit_rate'] < 80 ? 'warning' : 'success'),

            Stat::make('Slow Queries', $performanceMetrics['slow_queries_count'])
                ->description('Queries > 100ms')
                ->descriptionIcon('heroicon-m-exclamation-triangle')
                ->color($performanceMetrics['slow_queries_count'] > 10 ? 'danger' : 'success'),
        ];
    }
}
