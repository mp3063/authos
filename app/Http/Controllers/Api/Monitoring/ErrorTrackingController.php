<?php

namespace App\Http\Controllers\Api\Monitoring;

use App\Services\Monitoring\ErrorTrackingService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class ErrorTrackingController extends BaseController
{
    public function __construct(
        private readonly ErrorTrackingService $errorTrackingService
    ) {}

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
}
