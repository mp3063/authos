<?php

namespace App\Http\Controllers\Api\Monitoring;

use App\Http\Controllers\Controller;
use App\Services\Monitoring\ErrorTrackingService;
use App\Services\Monitoring\MetricsCollectionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class MetricsController extends Controller
{
    public function __construct(
        private readonly MetricsCollectionService $metricsService,
        private readonly ErrorTrackingService $errorTrackingService
    ) {}

    /**
     * Get all system metrics.
     */
    public function index(): JsonResponse
    {
        $metrics = $this->metricsService->collectAllMetrics();

        return response()->json($metrics);
    }

    /**
     * Get authentication metrics.
     */
    public function authentication(): JsonResponse
    {
        $metrics = $this->metricsService->getAuthenticationMetrics();

        return response()->json($metrics);
    }

    /**
     * Get OAuth metrics.
     */
    public function oauth(): JsonResponse
    {
        $metrics = $this->metricsService->getOAuthMetrics();

        return response()->json($metrics);
    }

    /**
     * Get API metrics.
     */
    public function api(): JsonResponse
    {
        $metrics = $this->metricsService->getApiMetrics();

        return response()->json($metrics);
    }

    /**
     * Get webhook metrics.
     */
    public function webhooks(): JsonResponse
    {
        $metrics = $this->metricsService->getWebhookMetrics();

        return response()->json($metrics);
    }

    /**
     * Get user metrics.
     */
    public function users(): JsonResponse
    {
        $metrics = $this->metricsService->getUserMetrics();

        return response()->json($metrics);
    }

    /**
     * Get organization metrics.
     */
    public function organizations(): JsonResponse
    {
        $metrics = $this->metricsService->getOrganizationMetrics();

        return response()->json($metrics);
    }

    /**
     * Get MFA metrics.
     */
    public function mfa(): JsonResponse
    {
        $metrics = $this->metricsService->getMfaMetrics();

        return response()->json($metrics);
    }

    /**
     * Get performance metrics.
     */
    public function performance(): JsonResponse
    {
        $metrics = $this->metricsService->getPerformanceMetrics();

        return response()->json($metrics);
    }

    /**
     * Get error statistics.
     */
    public function errors(Request $request): JsonResponse
    {
        $date = $request->query('date');
        $stats = $this->errorTrackingService->getErrorStatistics($date);

        return response()->json($stats);
    }

    /**
     * Get error trends.
     */
    public function errorTrends(Request $request): JsonResponse
    {
        $days = $request->query('days', 7);
        $trends = $this->errorTrackingService->getErrorTrends($days);

        return response()->json([
            'trends' => $trends,
            'days' => $days,
        ]);
    }

    /**
     * Get recent errors.
     */
    public function recentErrors(Request $request): JsonResponse
    {
        $limit = $request->query('limit', 50);
        $errors = $this->errorTrackingService->getRecentErrors($limit);

        return response()->json([
            'errors' => $errors,
            'count' => count($errors),
        ]);
    }

    /**
     * Record a custom metric.
     */
    public function recordMetric(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'value' => 'required|numeric',
            'tags' => 'array',
        ]);

        $this->metricsService->recordMetric(
            $validated['name'],
            $validated['value'],
            $validated['tags'] ?? []
        );

        return response()->json([
            'message' => 'Metric recorded successfully',
            'metric' => $validated['name'],
        ]);
    }

    /**
     * Get a specific custom metric.
     */
    public function getMetric(Request $request, string $name): JsonResponse
    {
        $date = $request->query('date');
        $metric = $this->metricsService->getMetric($name, $date);

        if (! $metric) {
            return response()->json([
                'error' => 'Metric not found',
            ], 404);
        }

        return response()->json($metric);
    }
}
