<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\Webhook\StoreWebhookRequest;
use App\Http\Requests\Webhook\UpdateWebhookRequest;
use App\Http\Resources\WebhookResource;
use App\Models\Webhook;
use App\Services\WebhookService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class WebhookController extends BaseApiController
{
    public function __construct(
        protected WebhookService $webhookService
    ) {
        $this->middleware('auth:api');
    }

    /**
     * Display a paginated listing of webhooks
     *
     * @group Webhook Management
     */
    public function index(Request $request): JsonResponse
    {
        $this->authorize('webhooks.read');

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,url,created_at,updated_at,last_delivered_at',
            'order' => 'sometimes|string|in:asc,desc',
            'is_active' => 'sometimes|boolean',
            'event' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $query = Webhook::query()->with(['organization']);

        // Enforce organization-based data isolation for non-super-admin users
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        // Apply filters
        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%$search%")
                    ->orWhere('url', 'LIKE', "%$search%")
                    ->orWhere('description', 'LIKE', "%$search%");
            });
        }

        if ($request->has('is_active')) {
            $query->where('is_active', $request->boolean('is_active'));
        }

        // Support filter[is_active] parameter
        if ($request->has('filter.is_active')) {
            $query->where('is_active', $request->boolean('filter.is_active'));
        }

        if ($request->has('event')) {
            $query->whereJsonContains('events', $request->event);
        }

        // Apply sorting
        $sort = $request->input('sort', 'created_at');
        $order = $request->input('order', 'desc');
        $query->orderBy($sort, $order);

        // Paginate
        $perPage = $request->input('per_page', 15);
        $webhooks = $query->paginate($perPage);

        return $this->paginatedResponse(
            $webhooks,
            null,
            WebhookResource::class
        );
    }

    /**
     * Store a newly created webhook
     *
     * @group Webhook Management
     */
    public function store(StoreWebhookRequest $request): JsonResponse
    {
        $this->authorize('webhooks.create');

        try {
            $organization = $this->getCurrentOrganization();

            if (! $organization) {
                return $this->errorResponse(
                    'Organization not found',
                    Response::HTTP_BAD_REQUEST
                );
            }

            $webhook = $this->webhookService->createWebhook(
                $organization,
                $request->validated()
            );

            return $this->createdResourceResponse(
                $webhook,
                WebhookResource::class,
                'Webhook created successfully'
            );
        } catch (\Illuminate\Validation\ValidationException $e) {
            return $this->validationErrorResponse($e->errors(), $e->getMessage());
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to create webhook: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Display the specified webhook
     *
     * @group Webhook Management
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('webhooks.read');

        $query = Webhook::with(['organization', 'deliveries' => function ($query) {
            $query->latest()->limit(10);
        }]);

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        return $this->resourceResponse(
            $webhook,
            WebhookResource::class
        );
    }

    /**
     * Update the specified webhook
     *
     * @group Webhook Management
     */
    public function update(UpdateWebhookRequest $request, string $id): JsonResponse
    {
        $this->authorize('webhooks.update');

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        try {
            $updatedWebhook = $this->webhookService->updateWebhook(
                $webhook,
                $request->validated()
            );

            return $this->updatedResourceResponse(
                $updatedWebhook,
                WebhookResource::class,
                'Webhook updated successfully'
            );
        } catch (\Illuminate\Validation\ValidationException $e) {
            return $this->validationErrorResponse($e->errors(), $e->getMessage());
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to update webhook: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Remove the specified webhook
     *
     * @group Webhook Management
     */
    public function destroy(string $id): JsonResponse
    {
        $this->authorize('webhooks.delete');

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        try {
            $this->webhookService->deleteWebhook($webhook);

            return $this->noContentResponse();
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to delete webhook: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Send a test webhook delivery
     *
     * @group Webhook Actions
     */
    public function test(string $id): JsonResponse
    {
        $this->authorize('webhooks.update');

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        try {
            $delivery = $this->webhookService->testWebhook($webhook);

            return $this->successResponse(
                [
                    'message' => 'Test webhook sent successfully',
                    'delivery_id' => $delivery->id,
                    'status' => $delivery->status?->value ?? $delivery->status,
                    'status_code' => $delivery->http_status_code,
                    'response_time_ms' => $delivery->response_time_ms,
                    'sent_at' => $delivery->sent_at?->toISOString(),
                ],
                'Test webhook sent successfully'
            );
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to send test webhook: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Rotate webhook secret
     *
     * @group Webhook Actions
     */
    public function rotateSecret(string $id): JsonResponse
    {
        $this->authorize('webhooks.update');

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        try {
            $newSecret = $this->webhookService->rotateSecret($webhook);

            return $this->successResponse(
                [
                    'secret' => $newSecret,
                    'message' => 'Webhook secret rotated successfully',
                ],
                'Webhook secret rotated successfully'
            );
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to rotate webhook secret: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Enable a webhook
     *
     * @group Webhook Actions
     */
    public function enable(string $id): JsonResponse
    {
        $this->authorize('webhooks.update');

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        if ($webhook->is_active) {
            return $this->errorResponse(
                'Webhook is already enabled',
                Response::HTTP_BAD_REQUEST
            );
        }

        try {
            $this->webhookService->enableWebhook($webhook);

            return $this->successResponse(
                ['is_active' => true],
                'Webhook enabled successfully'
            );
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to enable webhook: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Disable a webhook
     *
     * @group Webhook Actions
     */
    public function disable(string $id): JsonResponse
    {
        $this->authorize('webhooks.update');

        $query = Webhook::query();

        // Enforce organization-based data isolation
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $this->getAuthenticatedUser()->organization_id);
        }

        $webhook = $query->find($id);

        if (! $webhook) {
            return $this->notFoundResponse('Webhook not found');
        }

        if (! $webhook->is_active) {
            return $this->errorResponse(
                'Webhook is already disabled',
                Response::HTTP_BAD_REQUEST
            );
        }

        try {
            $this->webhookService->disableWebhook($webhook);

            return $this->successResponse(
                ['is_active' => false],
                'Webhook disabled successfully'
            );
        } catch (\Exception $e) {
            return $this->errorResponse(
                'Failed to disable webhook: '.$e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Get delivery history for a webhook
     *
     * @group Webhook Analytics
     */
    public function deliveries(Request $request, string $id): JsonResponse
    {
        $this->authorize('webhooks.read');

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'status' => 'sometimes|string|in:pending,sending,success,failed,retrying',
            'event_type' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

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
            \App\Http\Resources\WebhookDeliveryResource::class
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

        $validator = Validator::make($request->all(), [
            'days' => 'sometimes|integer|min:1|max:90',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

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
