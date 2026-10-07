<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Resources\WebhookDeliveryResource;
use App\Models\Webhook;
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
        $this->authorize('webhooks.update');

        // Find the delivery with its webhook
        $delivery = WebhookDelivery::with('webhook')->find($id);

        if (! $delivery) {
            return $this->notFoundResponse('Webhook delivery not found');
        }

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $webhook = $delivery->webhook;
            if (! $webhook || $webhook->organization_id !== $this->getAuthenticatedUser()->organization_id) {
                return $this->forbiddenResponse('You do not have permission to retry this delivery');
            }
        }

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
        $this->authorize('webhooks.read');

        // Find the webhook first
        $webhookQuery = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $webhookQuery->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $webhookQuery->find($webhookId);

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
        $this->authorize('webhooks.read');

        $request->validate([
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'status' => 'sometimes|string|in:pending,sending,success,failed,retrying',
            'event_type' => 'sometimes|string',
        ]);

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

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
        $this->authorize('webhooks.read');

        $request->validate([
            'days' => 'sometimes|integer|min:1|max:90',
        ]);

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        $days = $request->input('days', 30);
        $stats = $this->webhookService->getDeliveryStats($webhook, $days);

        return $this->successResponse($stats);
    }
}
