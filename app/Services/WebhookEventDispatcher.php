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
