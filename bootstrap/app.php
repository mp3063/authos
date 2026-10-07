<?php

use App\Http\Middleware\ApiMonitoring;
use App\Http\Middleware\ApiResponseCache;
use App\Http\Middleware\ApiVersioning;
use App\Http\Middleware\EnforceOrganizationBoundary;
use App\Http\Middleware\OAuthSecurity;
use App\Http\Middleware\SanitizeApiResponse;
use App\Http\Middleware\SecurityHeaders;
use App\Http\Middleware\SetPermissionContext;
use App\Http\Traits\ApiErrorResponse;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Laravel\Passport\Http\Middleware\CheckToken;
use Laravel\Passport\Http\Middleware\CheckTokenForAnyScope;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // Configure trusted proxies for proper IP address detection
        // In production, specify actual proxy IPs instead of '*'
        $middleware->trustProxies(
            at: env('TRUSTED_PROXIES', '*'),
            headers: Request::HEADER_X_FORWARDED_FOR |
                    Request::HEADER_X_FORWARDED_HOST |
                    Request::HEADER_X_FORWARDED_PORT |
                    Request::HEADER_X_FORWARDED_PROTO
        );

        $middleware->web(append: [
            SecurityHeaders::class,
        ]);

        // API middleware setup for Passport OAuth

        $middleware->web(append: [
            HandleCors::class,
        ]);

        $middleware->api(append: [
            HandleCors::class,
            SecurityHeaders::class,
            SetPermissionContext::class,
            SanitizeApiResponse::class,
        ]);

        $middleware->throttleApi();

        $middleware->alias([
            'scopes' => CheckToken::class,
            'scope' => CheckTokenForAnyScope::class,
            'oauth.security' => OAuthSecurity::class,
            'api.version' => ApiVersioning::class,
            'api.cache' => ApiResponseCache::class,
            'api.monitor' => ApiMonitoring::class,
            'org.boundary' => EnforceOrganizationBoundary::class,
            'permission.context' => SetPermissionContext::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Use standardized error responses for API requests
        $exceptions->render(function (ValidationException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use ApiErrorResponse;
                })->validationErrorResponse($e);
            }
        });

        $exceptions->render(function (AuthenticationException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use ApiErrorResponse;
                })->authenticationErrorResponse('Unauthenticated.');
            }
        });

        $exceptions->render(function (AuthorizationException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use ApiErrorResponse;
                })->authorizationErrorResponse('Insufficient permissions');
            }
        });

        $exceptions->render(function (AccessDeniedHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use ApiErrorResponse;
                })->authorizationErrorResponse('Insufficient permissions');
            }
        });

        $exceptions->render(function (NotFoundHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use ApiErrorResponse;
                })->notFoundErrorResponse();
            }
        });

        $exceptions->render(function (MethodNotAllowedHttpException $e, $request) {
            if ($request->is('api/*')) {
                return (new class
                {
                    use ApiErrorResponse;
                })->errorResponse(
                    'Method not allowed',
                    405,
                    'method_not_allowed',
                    ['allowed_methods' => $e->getHeaders()['Allow'] ?? null],
                    $e
                );
            }
        });

        $exceptions->render(function (TooManyRequestsHttpException $e, $request) {
            if ($request->is('api/*')) {
                $retryAfter = $e->getHeaders()['Retry-After'] ?? null;

                return (new class
                {
                    use ApiErrorResponse;
                })->rateLimitErrorResponse($retryAfter);
            }
        });

        // Catch-all for any other exceptions in API routes
        $exceptions->render(function (Throwable $e, $request) {
            if ($request->is('api/*')) {
                // Don't catch HTTP exceptions that were already handled above
                if ($e instanceof HttpException) {
                    return null; // Let other handlers manage it
                }

                return (new class
                {
                    use ApiErrorResponse;
                })->serverErrorResponse(
                    app()->environment(['local', 'development']) ? $e->getMessage() : null,
                    $e
                );
            }
        });
    })->create();
