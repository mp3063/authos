<?php

namespace App\Http\Controllers\Api\Monitoring;

use App\Http\Controllers\Controller;
use App\Services\Monitoring\HealthCheckService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class HealthCheckController extends Controller
{
    public function __construct(
        private readonly HealthCheckService $healthCheckService
    ) {}

    /**
     * Basic health check (liveness probe).
     */
    public function index(): JsonResponse
    {
        return response()->json([
            'status' => 'ok',
            'timestamp' => now()->toIso8601String(),
        ]);
    }

    /**
     * Detailed health check.
     */
    public function detailed(): JsonResponse
    {
        $health = $this->healthCheckService->checkHealth(detailed: true);

        $statusCode = match ($health['status']) {
            'healthy' => 200,
            'degraded' => 200,
            'unhealthy' => 503,
            'critical' => 503,
            default => 200,
        };

        return response()->json($health, $statusCode);
    }

    /**
     * Kubernetes readiness probe.
     */
    public function readiness(): JsonResponse
    {
        $readiness = $this->healthCheckService->checkReadiness();

        return response()->json($readiness, $readiness['ready'] ? 200 : 503);
    }

    /**
     * Kubernetes liveness probe.
     */
    public function liveness(): JsonResponse
    {
        $liveness = $this->healthCheckService->checkLiveness();

        return response()->json($liveness);
    }

    /**
     * Component-specific health check.
     */
    public function component(Request $request, string $component): JsonResponse
    {
        $validComponents = ['database', 'cache', 'oauth', 'storage', 'queue', 'ldap', 'email'];

        if (! in_array($component, $validComponents)) {
            return response()->json([
                'error' => 'Invalid component',
                'valid_components' => $validComponents,
            ], 404);
        }

        $method = 'check'.ucfirst($component);

        if (! method_exists($this->healthCheckService, $method)) {
            return response()->json([
                'error' => 'Component check not implemented',
            ], 404);
        }

        $result = $this->healthCheckService->$method();

        $statusCode = match ($result['status']) {
            'healthy' => 200,
            'degraded' => 200,
            'unhealthy' => 503,
            'not_configured' => 200,
            default => 200,
        };

        return response()->json([
            'component' => $component,
            'result' => $result,
            'timestamp' => now()->toIso8601String(),
        ], $statusCode);
    }
}
