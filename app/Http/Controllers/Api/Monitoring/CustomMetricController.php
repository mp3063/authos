<?php

namespace App\Http\Controllers\Api\Monitoring;

use App\Services\Monitoring\MetricsCollectionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class CustomMetricController extends BaseController
{
    public function __construct(
        private readonly MetricsCollectionService $metricsService
    ) {}

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
