<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\CacheInvalidationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CacheController extends Controller
{
    protected CacheInvalidationService $cacheService;

    public function __construct(CacheInvalidationService $cacheService)
    {
        $this->cacheService = $cacheService;
        $this->middleware('auth:api');
    }

    /**
     * Get cache statistics.
     */
    public function stats(): JsonResponse
    {
        $this->authorize('system.cache.read');

        $stats = $this->cacheService->getCacheStats();

        return response()->json([
            'data' => $stats,
        ]);
    }

    /**
     * Clear all API caches.
     */
    public function clearAll(): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $this->cacheService->invalidateAllApiCaches();

        return response()->json([
            'message' => 'All API caches cleared successfully',
        ]);
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
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $this->cacheService->invalidateEndpointCaches($request->endpoint);

        return response()->json([
            'message' => 'Endpoint caches cleared successfully',
            'endpoint' => $request->endpoint,
        ]);
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
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $this->cacheService->invalidateUserCaches($request->user_id);

        return response()->json([
            'message' => 'User caches cleared successfully',
            'user_id' => $request->user_id,
        ]);
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
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $this->cacheService->invalidateOrganizationCaches($request->organization_id);

        return response()->json([
            'message' => 'Organization caches cleared successfully',
            'organization_id' => $request->organization_id,
        ]);
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
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $application = \App\Models\Application::findOrFail($request->application_id);
        
        $this->cacheService->invalidateApplicationCaches(
            $application->id,
            $application->organization_id
        );

        return response()->json([
            'message' => 'Application caches cleared successfully',
            'application_id' => $request->application_id,
        ]);
    }

    /**
     * Clear expired caches.
     */
    public function clearExpired(): JsonResponse
    {
        $this->authorize('system.cache.clear');

        $clearedCount = $this->cacheService->clearExpiredCaches();

        return response()->json([
            'message' => 'Expired caches cleared successfully',
            'cleared_count' => $clearedCount,
        ]);
    }
}