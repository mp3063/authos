<?php

namespace App\Providers;

use App\Database\TestingSQLiteConnection;
use Illuminate\Database\Connection;
use Illuminate\Support\ServiceProvider;

class TestingServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Only register in testing environment
        if (! $this->app->environment('testing')) {
            return;
        }

        // Replace SQLite connection resolver with our custom one that handles PHP 8.4 nested transactions
        // The resolver receives: ($pdo, $database, $tablePrefix, $config)
        Connection::resolverFor('sqlite', function ($pdo, $database, $tablePrefix, $config) {
            return new TestingSQLiteConnection($pdo, $database, $tablePrefix, $config);
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        //
    }
}
