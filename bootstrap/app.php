<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->web(append: [
            \App\Http\Middleware\SecurityHeaders::class,
        ]);
        
        // API middleware setup for Passport OAuth
        
        $middleware->web(append: [
            \Illuminate\Http\Middleware\HandleCors::class,
        ]);
        
        $middleware->api(append: [
            \Illuminate\Http\Middleware\HandleCors::class,
        ]);

        $middleware->throttleApi();
        
        $middleware->alias([
            'auth.passport' => \Laravel\Passport\Http\Middleware\CheckClientCredentials::class,
            'oauth.security' => \App\Http\Middleware\OAuthSecurity::class,
            'api.rate_limit' => \App\Http\Middleware\ApiRateLimiter::class,
            'api.version' => \App\Http\Middleware\ApiVersioning::class,
            'api.cache' => \App\Http\Middleware\ApiResponseCache::class,
            'api.monitor' => \App\Http\Middleware\ApiMonitoring::class,
            'org.boundary' => \App\Http\Middleware\EnforceOrganizationBoundary::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
