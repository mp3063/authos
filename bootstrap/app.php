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
            \App\Http\Middleware\SanitizeApiResponse::class,
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
        // Use standardized error responses for API requests
        $exceptions->render(function (\Illuminate\Validation\ValidationException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->validationErrorResponse($e);
            }
        });

        $exceptions->render(function (\Illuminate\Auth\AuthenticationException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->authenticationErrorResponse('Unauthenticated.');
            }
        });

        $exceptions->render(function (\Illuminate\Auth\Access\AuthorizationException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->authorizationErrorResponse('Insufficient permissions');
            }
        });

        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->authorizationErrorResponse('Insufficient permissions');
            }
        });

        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\NotFoundHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->notFoundErrorResponse();
            }
        });

        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->errorResponse(
                    'Method not allowed',
                    405,
                    'method_not_allowed',
                    ['allowed_methods' => $e->getHeaders()['Allow'] ?? null],
                    $e
                );
            }
        });

        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->rateLimitErrorResponse($e->getRetryAfter());
            }
        });

        // Catch-all for any other exceptions in API routes
        $exceptions->render(function (\Throwable $e, $request) {
            if ($request->is('api/*')) {
                // Don't catch HTTP exceptions that were already handled above
                if ($e instanceof \Symfony\Component\HttpKernel\Exception\HttpException) {
                    return null; // Let other handlers manage it
                }

                return (new class
                {
                    use \App\Http\Traits\ApiErrorResponse;
                })->serverErrorResponse(
                    app()->environment(['local', 'development']) ? $e->getMessage() : null,
                    $e
                );
            }
        });
    })->create();
