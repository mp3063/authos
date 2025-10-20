<?php

return [
    App\Providers\TestingServiceProvider::class, // Must be first to override SQLite connection
    App\Providers\AppServiceProvider::class,
    App\Providers\AuthorizationServiceProvider::class,
    App\Providers\EventServiceProvider::class,
    App\Providers\Filament\AdminPanelProvider::class,
];
