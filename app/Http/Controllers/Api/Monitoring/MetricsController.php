<?php

namespace App\Http\Controllers\Api\Monitoring;

use App\Services\Monitoring\MetricsCollectionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller as BaseController;

class MetricsController extends BaseController
{
    public function __construct(
        private readonly MetricsCollectionService $metricsService
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
}
