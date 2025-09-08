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
            \App\Http\Middleware\SecurityHeaders::class,
            \App\Http\Middleware\SetPermissionContext::class,
        ]);

        $middleware->throttleApi();
        
        $middleware->alias([
            'scopes' => \Laravel\Passport\Http\Middleware\CheckToken::class,
            'scope' => \Laravel\Passport\Http\Middleware\CheckTokenForAnyScope::class,
            'oauth.security' => \App\Http\Middleware\OAuthSecurity::class,
            'api.rate_limit' => \App\Http\Middleware\ApiRateLimiter::class,
            'api.version' => \App\Http\Middleware\ApiVersioning::class,
            'api.cache' => \App\Http\Middleware\ApiResponseCache::class,
            'api.monitor' => \App\Http\Middleware\ApiMonitoring::class,
            'org.boundary' => \App\Http\Middleware\EnforceOrganizationBoundary::class,
            'permission.context' => \App\Http\Middleware\SetPermissionContext::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Customize authorization exception messages for API
        $exceptions->render(function (\Illuminate\Auth\Access\AuthorizationException $e, $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'message' => 'Insufficient permissions',
                    'exception' => 'Illuminate\\Auth\\Access\\AuthorizationException',
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'trace' => collect($e->getTrace())->map(function ($trace) {
                        return collect($trace)->only(['file', 'line', 'function', 'class', 'type']);
                    })->all(),
                ], 403);
            }
        });
        
        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e, $request) {
            if ($request->is('api/*')) {
                return response()->json([
                    'message' => 'Insufficient permissions',
                    'exception' => 'Symfony\\Component\\HttpKernel\\Exception\\AccessDeniedHttpException',
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                    'trace' => collect($e->getTrace())->map(function ($trace) {
                        return collect($trace)->only(['file', 'line', 'function', 'class', 'type']);
                    })->all(),
                ], 403);
            }
        });
    })->create();
