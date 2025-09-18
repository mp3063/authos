<?php

namespace App\Http\Controllers\Api\Organizations;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Controllers\Api\Traits\CacheableResponse;
use App\Models\Organization;
use App\Services\OrganizationAnalyticsService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;

class OrganizationAnalyticsController extends BaseApiController
{
    use CacheableResponse;

    protected OrganizationAnalyticsService $analyticsService;

    public function __construct(OrganizationAnalyticsService $analyticsService)
    {
        $this->analyticsService = $analyticsService;
        $this->middleware('auth:api');
    }

    /**
     * Get organization analytics
     */
    public function analytics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d,1y',
            'metrics' => 'sometimes|array',
            'metrics.*' => 'string|in:users,applications,authentication_logs,active_sessions',
            'timezone' => 'sometimes|string|timezone',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $metrics = $request->get('metrics', ['users', 'applications', 'authentication_logs']);
        $timezone = $request->get('timezone', 'UTC');

        // Cache analytics using the improved caching trait
        $cacheParams = compact('period', 'metrics', 'timezone');
        $analyticsData = $this->cacheAnalytics(
            "organization_{$organization->id}",
            $cacheParams,
            function () use ($organization, $period) {
                return $this->analyticsService->getAnalytics(
                    $organization,
                    $period
                );
            },
            300 // 5 minutes cache
        );

        return $this->successResponse(
            $analyticsData,
            'Organization analytics retrieved successfully'
        );
    }

    /**
     * Get user activity metrics
     */
    public function userMetrics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'type' => 'sometimes|string|in:registrations,logins,active_users',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $type = $request->get('type', 'active_users');

        $cacheParams = compact('period', 'type');
        $metrics = $this->cacheAnalytics(
            "user_metrics_{$organization->id}",
            $cacheParams,
            function () use ($organization, $period, $type) {
                return $this->analyticsService->getUserMetrics($organization->id, $period, $type);
            }
        );

        return $this->successResponse(
            $metrics,
            'User metrics retrieved successfully'
        );
    }

    /**
     * Get application usage metrics
     */
    public function applicationMetrics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'application_id' => 'sometimes|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $applicationId = $request->get('application_id');

        $cacheParams = compact('period', 'applicationId');
        $metrics = $this->cacheAnalytics(
            "app_metrics_{$organization->id}",
            $cacheParams,
            function () use ($organization, $period, $applicationId) {
                return $this->analyticsService->getApplicationMetrics($organization->id, $period, $applicationId);
            }
        );

        return $this->successResponse(
            $metrics,
            'Application metrics retrieved successfully'
        );
    }

    /**
     * Get security metrics
     */
    public function securityMetrics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'include_failed_attempts' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $includeFailedAttempts = $request->boolean('include_failed_attempts', true);

        $cacheParams = compact('period', 'includeFailedAttempts');
        $metrics = $this->cacheAnalytics(
            "security_metrics_{$organization->id}",
            $cacheParams,
            function () use ($organization, $period) {
                return $this->analyticsService->getSecurityMetrics($organization, $period);
            }
        );

        return $this->successResponse(
            $metrics,
            'Security metrics retrieved successfully'
        );
    }

    /**
     * Export organization data
     */
    public function export(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'format' => 'sometimes|string|in:json,csv,xlsx',
            'data_type' => 'required|string|in:users,applications,analytics,security_logs',
            'date_from' => 'sometimes|date|before_or_equal:date_to',
            'date_to' => 'sometimes|date|after_or_equal:date_from',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $format = $request->get('format', 'json');
        $dataType = $request->get('data_type');
        $dateFrom = $request->get('date_from');
        $dateTo = $request->get('date_to');

        try {
            $exportData = $this->analyticsService->exportOrganizationData(
                $organization->id,
                $dataType,
                $format,
                $dateFrom,
                $dateTo
            );

            return $this->successResponse(
                $exportData,
                'Organization data exported successfully'
            );
        } catch (\Exception $e) {
            return $this->errorResponse('Failed to export data: '.$e->getMessage(), 500);
        }
    }
}
