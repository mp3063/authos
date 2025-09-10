<?php

namespace App\Http\Middleware;

use App\Services\PerformanceMonitoringService;
use Closure;
use Illuminate\Http\Request;

/**
 * Middleware for monitoring API performance automatically
 */
class PerformanceMonitoringMiddleware
{
    protected PerformanceMonitoringService $performanceService;

    public function __construct(PerformanceMonitoringService $performanceService)
    {
        $this->performanceService = $performanceService;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        // Skip performance monitoring in testing environment
        if (app()->environment('testing')) {
            return $next($request);
        }

        $endpoint = $request->getPathInfo();

        // Only monitor API endpoints
        if (! str_starts_with($endpoint, '/api/')) {
            return $next($request);
        }

        return $this->performanceService->monitorEndpoint($endpoint, function () use ($next, $request) {
            return $next($request);
        });
    }
}
