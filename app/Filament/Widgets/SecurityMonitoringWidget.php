<?php

namespace App\Filament\Widgets;

use App\Services\Monitoring\ErrorTrackingService;
use App\Services\Monitoring\MetricsCollectionService;
use Filament\Widgets\Widget;

class SecurityMonitoringWidget extends Widget
{
    protected string $view = 'filament.widgets.security-monitoring-widget';

    protected static ?int $sort = 4;

    protected int|string|array $columnSpan = 'full';

    protected ?string $pollingInterval = '30s';

    public function getViewData(): array
    {
        $metricsService = app(MetricsCollectionService::class);
        $errorTrackingService = app(ErrorTrackingService::class);

        $authMetrics = $metricsService->getAuthenticationMetrics();
        $errorStats = $errorTrackingService->getErrorStatistics();

        return [
            'suspicious_ips' => $authMetrics['suspicious_ips'] ?? [],
            'failed_logins' => $authMetrics['today']['failed'] ?? 0,
            'critical_errors' => $errorStats['critical'] ?? 0,
            'error_rate' => $errorTrackingService->getErrorRate(),
        ];
    }
}
