<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Api\Traits\FindsOrgScopedWebhooks;
use App\Http\Resources\WebhookDeliveryResource;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use App\Services\WebhookService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Symfony\Component\HttpFoundation\Response;

class WebhookDeliveryController extends BaseController
{
    use ApiControllerHelpers;
    use FindsOrgScopedWebhooks;

    public function __construct(
        protected WebhookDeliveryService $deliveryService,
        protected WebhookService $webhookService
    ) {
        $this->middleware('auth:api');
    }

    /**
     * Manually retry a failed webhook delivery
     *
     * @group Webhook Delivery Management
     */
    public function retry(string $id): JsonResponse
    {
        $delivery = WebhookDelivery::with('webhook')->find($id);

        if (! $delivery) {
            return $this->notFoundResponse('Webhook delivery not found');
        }

        $this->authorize('update', $delivery);

        // Check if the delivery can be retried
        if (! $delivery->canRetry()) {
            $reason = $delivery->hasReachedMaxAttempts()
                ? 'Maximum retry attempts reached'
                : 'Delivery cannot be retried (current status: '.$delivery->status?->value.')';

            return $this->errorResponse(
                $reason,
                Response::HTTP_BAD_REQUEST
            );
        }

        try {
            // Reset the delivery for retry
            $delivery->scheduleRetry(0); // Retry immediately

            // Attempt delivery
            $this->deliveryService->deliver($delivery);

            // Refresh to get updated status
            $delivery->refresh();

            return $this->successResponse(
                new WebhookDeliveryResource($delivery),
                'Webhook delivery retry initiated successfully'
            );
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to retry webhook delivery: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Get a specific delivery with full details
     *
     * @group Webhook Delivery Management
     */
    public function show(string $webhookId, string $deliveryId): JsonResponse
    {
        $webhook = $this->findWebhookWithOrgScope($webhookId, 'view');

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        // Find the delivery
        $delivery = $webhook->deliveries()->find($deliveryId);

        if (! $delivery) {
            return $this->notFoundResponse('Webhook delivery not found');
        }

        return $this->resourceResponse(
            $delivery,
            WebhookDeliveryResource::class
        );
    }

    /**
     * Get delivery history for a webhook
     *
     * @group Webhook Analytics
     */
    public function deliveries(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'status' => 'sometimes|string|in:pending,sending,success,failed,retrying',
            'event_type' => 'sometimes|string',
        ]);

        $webhook = $this->findWebhookWithOrgScope($id, 'view');

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        $deliveriesQuery = $webhook->deliveries()->with('webhook');

        // Apply filters
        if ($request->has('status')) {
            $deliveriesQuery->where('status', $request->status);
        }

        if ($request->has('event_type')) {
            $deliveriesQuery->where('event_type', $request->event_type);
        }

        // Order by most recent
        $deliveriesQuery->latest();

        // Paginate
        $perPage = $request->input('per_page', 20);
        $deliveries = $deliveriesQuery->paginate($perPage);

        return $this->paginatedResponse(
            $deliveries,
            null,
            WebhookDeliveryResource::class
        );
    }

    /**
     * Get delivery statistics for a webhook
     *
     * @group Webhook Analytics
     */
    public function stats(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'days' => 'sometimes|integer|min:1|max:90',
        ]);

        $webhook = $this->findWebhookWithOrgScope($id, 'view');

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        $days = $request->input('days', 30);
        $stats = $this->webhookService->getDeliveryStats($webhook, $days);

        return $this->successResponse($stats);
    }
}
