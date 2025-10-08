<?php

namespace App\Services;

use App\Enums\WebhookEventType;
use App\Jobs\DeliverWebhookJob;
use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;

class WebhookEventDispatcher extends BaseService
{
    /**
     * Dispatch a webhook event
     */
    public function dispatch(string $eventType, Model $subject, array $payload = []): void
    {
        try {
            // Validate event type
            if (! WebhookEventType::isValid($eventType)) {
                $this->logAction('webhook_invalid_event_type', [
                    'event_type' => $eventType,
                ]);

                return;
            }

            // Get organization from subject
            $organization = $this->extractOrganization($subject);

            if (! $organization) {
                $this->logAction('webhook_no_organization', [
                    'event_type' => $eventType,
                    'subject_type' => get_class($subject),
                    'subject_id' => $subject->id,
                ]);

                return;
            }

            // Get webhooks subscribed to this event
            $webhooks = $this->getSubscribedWebhooks($organization, $eventType);

            if ($webhooks->isEmpty()) {
                $this->logAction('webhook_no_subscribers', [
                    'event_type' => $eventType,
                    'organization_id' => $organization->id,
                ]);

                return;
            }

            // Build payload
            $fullPayload = $this->buildPayload($eventType, $subject, $payload);

            // Create deliveries and dispatch jobs
            foreach ($webhooks as $webhook) {
                $this->createAndDispatchDelivery($webhook, $eventType, $fullPayload);
            }

            $this->logAction('webhook_event_dispatched', [
                'event_type' => $eventType,
                'organization_id' => $organization->id,
                'webhook_count' => $webhooks->count(),
            ]);

        } catch (\Exception $e) {
            $this->handleException($e, 'webhook_event_dispatch', [
                'event_type' => $eventType,
                'subject_type' => get_class($subject),
                'subject_id' => $subject->id ?? null,
            ]);
        }
    }

    /**
     * Get webhooks subscribed to event type
     */
    protected function getSubscribedWebhooks(Organization $organization, string $eventType): Collection
    {
        return Webhook::where('organization_id', $organization->id)
            ->active()
            ->subscribedTo($eventType)
            ->get();
    }

    /**
     * Build webhook payload
     */
    protected function buildPayload(string $eventType, Model $subject, array $extra = []): array
    {
        $payload = [
            'id' => 'wh_delivery_'.uniqid(),
            'event' => $eventType,
            'created_at' => now()->toISOString(),
            'data' => $this->buildEventData($eventType, $subject, $extra),
        ];

        // Add organization_id if available
        if ($organization = $this->extractOrganization($subject)) {
            $payload['organization_id'] = $organization->id;
        }

        // Add previous data for update events
        if (str_ends_with($eventType, '.updated') && isset($extra['previous'])) {
            $payload['previous'] = $extra['previous'];
            $payload['changes'] = $extra['changes'] ?? [];
        }

        // Add metadata
        $payload['metadata'] = array_merge([
            'source' => 'AuthOS',
            'version' => '1.0',
        ], $extra['metadata'] ?? []);

        return $payload;
    }

    /**
     * Build event-specific data
     */
    protected function buildEventData(string $eventType, Model $subject, array $extra): array
    {
        $data = [];

        // Common fields
        if (method_exists($subject, 'toArray')) {
            $data = $subject->toArray();
        }

        // Remove sensitive fields
        $sensitiveFields = ['password', 'remember_token', 'secret', 'client_secret', 'two_factor_secret'];
        foreach ($sensitiveFields as $field) {
            unset($data[$field]);
        }

        // Add context from extra data
        if (isset($extra['context'])) {
            $data = array_merge($data, $extra['context']);
        }

        return $data;
    }

    /**
     * Create delivery record and dispatch job
     */
    protected function createAndDispatchDelivery(
        Webhook $webhook,
        string $eventType,
        array $payload
    ): void {
        // Create delivery record
        $delivery = WebhookDelivery::create([
            'webhook_id' => $webhook->id,
            'event_type' => $eventType,
            'payload' => $payload,
            'status' => 'pending',
        ]);

        // Dispatch delivery job
        DeliverWebhookJob::dispatch($delivery);

        $this->logAction('webhook_delivery_created', [
            'delivery_id' => $delivery->id,
            'webhook_id' => $webhook->id,
            'event_type' => $eventType,
        ]);
    }

    /**
     * Extract organization from subject model
     */
    protected function extractOrganization(Model $subject): ?Organization
    {
        // Direct organization
        if ($subject instanceof Organization) {
            return $subject;
        }

        // Has organization relationship
        if (method_exists($subject, 'organization') && $subject->organization) {
            return $subject->organization;
        }

        // Has organization_id
        if (isset($subject->organization_id)) {
            return Organization::find($subject->organization_id);
        }

        return null;
    }

    /**
     * Extract organization ID from a model
     */
    public function extractOrganizationId($model): ?int
    {
        if ($model instanceof Organization) {
            return $model->id;
        }

        if (is_object($model) && property_exists($model, 'organization_id')) {
            return $model->organization_id;
        }

        if ($model instanceof Model) {
            $org = $this->extractOrganization($model);

            return $org?->id;
        }

        return null;
    }

    /**
     * Handle user created event
     */
    public function handleUserCreated($user): void
    {
        $payload = $this->buildUserPayload($user, 'user.created');
        $this->dispatchWebhooksForEvent('user.created', $payload, $user->organization_id);
    }

    /**
     * Handle user updated event
     */
    public function handleUserUpdated($user): void
    {
        $payload = $this->buildUserPayload($user, 'user.updated');
        $this->dispatchWebhooksForEvent('user.updated', $payload, $user->organization_id);
    }

    /**
     * Handle user deleted event
     */
    public function handleUserDeleted($user): void
    {
        $payload = $this->buildUserPayload($user, 'user.deleted');
        $this->dispatchWebhooksForEvent('user.deleted', $payload, $user->organization_id);
    }

    /**
     * Build user payload for webhook
     */
    public function buildUserPayload($user, string $eventType = 'user.event'): array
    {
        return [
            'id' => 'evt_'.\Illuminate\Support\Str::random(32),
            'event' => $eventType,
            'data' => $this->sanitizeUserData($user),
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $user->organization_id,
        ];
    }

    /**
     * Sanitize user data to remove sensitive fields
     */
    protected function sanitizeUserData($user): array
    {
        $data = is_array($user) ? $user : $user->toArray();

        // Remove sensitive fields
        $sensitiveFields = [
            'password',
            'remember_token',
            'two_factor_secret',
            'two_factor_recovery_codes',
        ];

        foreach ($sensitiveFields as $field) {
            unset($data[$field]);
        }

        return $data;
    }

    /**
     * Dispatch webhooks for a specific event
     */
    protected function dispatchWebhooksForEvent(string $eventType, array $payload, ?int $organizationId): void
    {
        if ($organizationId === null) {
            return;
        }

        // Get all active webhooks for this organization
        $webhooks = Webhook::where('organization_id', $organizationId)
            ->where('is_active', true)
            ->get();

        foreach ($webhooks as $webhook) {
            // Check if webhook is subscribed to this event type
            if (! $this->isSubscribedToEventType($webhook, $eventType)) {
                continue;
            }

            // Create webhook delivery record
            $delivery = WebhookDelivery::create([
                'webhook_id' => $webhook->id,
                'event_type' => $eventType,
                'payload' => $payload,
                'status' => 'pending',
                'signature' => '', // Will be generated by delivery service
            ]);

            // Dispatch the delivery job
            DeliverWebhookJob::dispatch($delivery);
        }
    }

    /**
     * Check if webhook is subscribed to the event type
     */
    protected function isSubscribedToEventType(Webhook $webhook, string $eventType): bool
    {
        $events = $webhook->events ?? [];

        // Check for wildcard subscription
        if (in_array('*', $events)) {
            return true;
        }

        // Check for exact match
        if (in_array($eventType, $events)) {
            return true;
        }

        // Check for pattern match (e.g., "user.*")
        foreach ($events as $subscribedEvent) {
            if (\Illuminate\Support\Str::is($subscribedEvent, $eventType)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if webhook should dispatch for event
     */
    public function shouldDispatch(Webhook $webhook, string $eventType): bool
    {
        // Webhook must be active
        if (! $webhook->is_active) {
            return false;
        }

        // Webhook must be subscribed to event
        if (! $webhook->isSubscribedTo($eventType)) {
            return false;
        }

        return true;
    }
}
