<?php

namespace App\Http\Controllers\Api;

use App\Models\Application;
use App\Services\CacheInvalidationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CacheController extends BaseApiController
{
    public function __construct(
        protected CacheInvalidationService $cacheService
    ) {
        $this->middleware('auth:api');
    }

    /**
     * Get cache statistics.
     */
    public function stats(): JsonResponse
    {
        $this->authorize('system.cache.read');

        $stats = $this->cacheService->getCacheStats();

        return $this->successResponse($stats);
    }

    /**
     * Clear all API caches.
     */
    public function clearAll(): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $this->cacheService->invalidateAllApiCaches();

        return $this->successResponse(null, 'All API caches cleared successfully');
    }

    /**
     * Clear caches for a specific endpoint.
     */
    public function clearEndpoint(Request $request): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $validator = Validator::make($request->all(), [
            'endpoint' => 'required|string|max:255',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $this->cacheService->invalidateEndpointCaches($request->endpoint);

        return $this->successResponse(
            ['endpoint' => $request->endpoint],
            'Endpoint caches cleared successfully'
        );
    }

    /**
     * Clear caches for a specific user.
     */
    public function clearUser(Request $request): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|integer|exists:users,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $this->cacheService->invalidateUserCaches($request->user_id);

        return $this->successResponse(
            ['user_id' => $request->user_id],
            'User caches cleared successfully'
        );
    }

    /**
     * Clear caches for a specific organization.
     */
    public function clearOrganization(Request $request): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $validator = Validator::make($request->all(), [
            'organization_id' => 'required|integer|exists:organizations,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $this->cacheService->invalidateOrganizationCaches($request->organization_id);

        return $this->successResponse(
            ['organization_id' => $request->organization_id],
            'Organization caches cleared successfully'
        );
    }

    /**
     * Clear caches for a specific application.
     */
    public function clearApplication(Request $request): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $validator = Validator::make($request->all(), [
            'application_id' => 'required|integer|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $application = Application::findOrFail($request->application_id);

        $this->cacheService->invalidateApplicationCaches(
            $application->id,
            $application->organization_id
        );

        return $this->successResponse(
            ['application_id' => $request->application_id],
            'Application caches cleared successfully'
        );
    }

    /**
     * Clear expired caches.
     */
    public function clearExpired(): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $clearedCount = $this->cacheService->clearExpiredCaches();

        return $this->successResponse(
            ['cleared_count' => $clearedCount],
            'Expired caches cleared successfully'
        );
    }
}
