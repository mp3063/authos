<?php

namespace App\Filament\Widgets;

use App\Services\Monitoring\HealthCheckService;
use Filament\Widgets\Widget;

class SystemHealthWidget extends Widget
{
    protected string $view = 'filament.widgets.system-health-widget';

    protected static ?int $sort = 0;

    protected int|string|array $columnSpan = 'full';

    public function __construct(
        private readonly HealthCheckService $healthCheckService
    ) {
        parent::__construct();
    }

    public function getViewData(): array
    {
        $health = $this->healthCheckService->checkHealth(detailed: false);

        return [
            'status' => $health['status'],
            'checks' => $health['checks'],
            'timestamp' => $health['timestamp'],
        ];
    }
}
