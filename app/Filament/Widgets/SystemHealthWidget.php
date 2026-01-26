<?php

namespace App\Filament\Widgets;

use App\Services\Monitoring\HealthCheckService;
use Filament\Widgets\Widget;

class SystemHealthWidget extends Widget
{
    protected string $view = 'filament.widgets.system-health-widget';

    protected static ?int $sort = 0;

    protected int|string|array $columnSpan = 'full';

    public function getViewData(): array
    {
        $health = app(HealthCheckService::class)->checkHealth(detailed: false);

        return [
            'status' => $health['status'],
            'checks' => $health['checks'],
            'timestamp' => $health['timestamp'],
        ];
    }
}
