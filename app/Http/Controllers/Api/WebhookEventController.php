<?php

namespace App\Http\Controllers\Api;

use App\Http\Resources\WebhookEventResource;
use App\Models\WebhookEvent;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;

class WebhookEventController extends BaseApiController
{
    public function __construct()
    {
        $this->middleware('auth:api');
    }

    /**
     * List all available webhook events
     *
     * @group Webhook Events
     */
    public function index(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'category' => 'sometimes|string|in:user,organization,application,auth,sso,system',
            'is_active' => 'sometimes|boolean',
            'include_schema' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        // Cache the webhook events list for 1 hour
        $cacheKey = 'webhook_events:'
            .($request->input('category', 'all'))
            .':'.$request->boolean('is_active', true)
            .':'.$request->boolean('include_schema', false);

        $events = Cache::remember($cacheKey, 3600, function () use ($request) {
            $query = WebhookEvent::query();

            // Apply filters
            if ($request->has('category')) {
                $query->category($request->category);
            }

            if ($request->has('is_active')) {
                if ($request->boolean('is_active')) {
                    $query->active();
                } else {
                    $query->where('is_active', false);
                }
            } else {
                // By default, only show active events
                $query->active();
            }

            // Order by category and name
            $query->orderBy('category')->orderBy('name');

            return $query->get();
        });

        return $this->collectionResponse(
            WebhookEventResource::collection($events),
            null
        );
    }

    /**
     * Get a specific webhook event
     *
     * @group Webhook Events
     */
    public function show(string $id): JsonResponse
    {
        $event = WebhookEvent::find($id);

        if (! $event) {
            return $this->notFoundResponse('Webhook event not found');
        }

        return $this->resourceResponse(
            $event,
            WebhookEventResource::class
        );
    }

    /**
     * Get webhook events grouped by category
     *
     * @group Webhook Events
     */
    public function groupedByCategory(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        // Cache the grouped events for 1 hour
        $cacheKey = 'webhook_events:grouped:'.$request->boolean('is_active', true);

        $groupedEvents = Cache::remember($cacheKey, 3600, function () use ($request) {
            $query = WebhookEvent::query();

            if ($request->has('is_active')) {
                if ($request->boolean('is_active')) {
                    $query->active();
                } else {
                    $query->where('is_active', false);
                }
            } else {
                // By default, only show active events
                $query->active();
            }

            $events = $query->orderBy('category')->orderBy('name')->get();

            // Group by category
            return $events->groupBy('category')->map(function ($categoryEvents, $category) {
                return [
                    'category' => $category,
                    'events' => WebhookEventResource::collection($categoryEvents),
                ];
            })->values();
        });

        return $this->successResponse($groupedEvents);
    }
}
