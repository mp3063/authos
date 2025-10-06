<?php

namespace App\Services;

use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Support\Collection;
use Illuminate\Validation\ValidationException;

class WebhookService extends BaseService
{
    public function __construct(
        protected WebhookSignatureService $signatureService
    ) {}

    /**
     * Create a new webhook for an organization
     */
    public function createWebhook(Organization $organization, array $data): Webhook
    {
        return $this->executeInTransaction(function () use ($organization, $data) {
            $this->validateWebhookUrl($data['url']);

            // Generate secret if not provided
            if (! isset($data['secret'])) {
                $data['secret'] = $this->signatureService->generateSecret();
            }

            $data['organization_id'] = $organization->id;

            $webhook = Webhook::create($data);

            $this->logAction('webhook_created', [
                'webhook_id' => $webhook->id,
                'organization_id' => $organization->id,
                'url' => $webhook->url,
            ]);

            return $webhook;
        });
    }

    /**
     * Update an existing webhook
     */
    public function updateWebhook(Webhook $webhook, array $data): Webhook
    {
        return $this->executeInTransaction(function () use ($webhook, $data) {
            if (isset($data['url'])) {
                $this->validateWebhookUrl($data['url']);
            }

            $webhook->update($data);

            $this->logAction('webhook_updated', [
                'webhook_id' => $webhook->id,
                'organization_id' => $webhook->organization_id,
            ]);

            return $webhook->fresh();
        });
    }

    /**
     * Delete a webhook
     */
    public function deleteWebhook(Webhook $webhook): bool
    {
        return $this->executeInTransaction(function () use ($webhook) {
            $webhookId = $webhook->id;
            $organizationId = $webhook->organization_id;

            $deleted = $webhook->delete();

            $this->logAction('webhook_deleted', [
                'webhook_id' => $webhookId,
                'organization_id' => $organizationId,
            ]);

            return $deleted;
        });
    }

    /**
     * Enable a webhook
     */
    public function enableWebhook(Webhook $webhook): bool
    {
        $webhook->update([
            'is_active' => true,
            'failure_count' => 0,
        ]);

        $this->logAction('webhook_enabled', [
            'webhook_id' => $webhook->id,
            'organization_id' => $webhook->organization_id,
        ]);

        return true;
    }

    /**
     * Disable a webhook
     */
    public function disableWebhook(Webhook $webhook): bool
    {
        $webhook->update(['is_active' => false]);

        $this->logAction('webhook_disabled', [
            'webhook_id' => $webhook->id,
            'organization_id' => $webhook->organization_id,
        ]);

        return true;
    }

    /**
     * Rotate webhook secret
     */
    public function rotateSecret(Webhook $webhook): string
    {
        return $this->executeInTransaction(function () use ($webhook) {
            $newSecret = $this->signatureService->generateSecret();

            $webhook->update(['secret' => $newSecret]);

            $this->logAction('webhook_secret_rotated', [
                'webhook_id' => $webhook->id,
                'organization_id' => $webhook->organization_id,
            ]);

            return $newSecret;
        });
    }

    /**
     * Get webhooks subscribed to a specific event type
     */
    public function getSubscribedWebhooks(Organization $organization, string $eventType): Collection
    {
        return Webhook::where('organization_id', $organization->id)
            ->active()
            ->subscribedTo($eventType)
            ->get();
    }

    /**
     * Get delivery statistics for a webhook
     */
    public function getDeliveryStats(Webhook $webhook, ?int $days = 30): array
    {
        $deliveries = $webhook->deliveries()
            ->where('created_at', '>=', now()->subDays($days))
            ->get();

        $totalDeliveries = $deliveries->count();
        $successfulDeliveries = $deliveries->where('status', 'success')->count();
        $failedDeliveries = $deliveries->where('status', 'failed')->count();
        $retryingDeliveries = $deliveries->where('status', 'retrying')->count();

        $successRate = $totalDeliveries > 0
            ? round(($successfulDeliveries / $totalDeliveries) * 100, 2)
            : 0;

        $avgDeliveryTime = $deliveries
            ->where('status', 'success')
            ->whereNotNull('request_duration_ms')
            ->avg('request_duration_ms');

        return [
            'total_deliveries' => $totalDeliveries,
            'successful_deliveries' => $successfulDeliveries,
            'failed_deliveries' => $failedDeliveries,
            'retrying_deliveries' => $retryingDeliveries,
            'success_rate' => $successRate,
            'average_delivery_time_ms' => $avgDeliveryTime ? round($avgDeliveryTime) : null,
            'period_days' => $days,
        ];
    }

    /**
     * Get delivery history for a webhook
     */
    public function getDeliveryHistory(Webhook $webhook, int $limit = 50): Collection
    {
        return $webhook->deliveries()
            ->latest()
            ->limit($limit)
            ->get();
    }

    /**
     * Test a webhook by sending a test payload
     */
    public function testWebhook(Webhook $webhook): WebhookDelivery
    {
        $testPayload = [
            'id' => 'test_'.uniqid(),
            'event' => 'webhook.test',
            'created_at' => now()->toISOString(),
            'organization_id' => $webhook->organization_id,
            'data' => [
                'message' => 'This is a test webhook delivery',
                'webhook_id' => $webhook->id,
                'webhook_name' => $webhook->name,
            ],
        ];

        $delivery = WebhookDelivery::create([
            'webhook_id' => $webhook->id,
            'event_type' => 'webhook.test',
            'payload' => $testPayload,
            'status' => 'pending',
        ]);

        // Dispatch the delivery job
        app(WebhookDeliveryService::class)->deliver($delivery);

        $this->logAction('webhook_tested', [
            'webhook_id' => $webhook->id,
            'delivery_id' => $delivery->id,
        ]);

        return $delivery->fresh();
    }

    /**
     * Validate webhook URL
     *
     * @throws ValidationException
     */
    protected function validateWebhookUrl(string $url): void
    {
        // Parse URL
        $parsed = parse_url($url);

        if ($parsed === false || ! isset($parsed['scheme'], $parsed['host'])) {
            throw ValidationException::withMessages([
                'url' => ['Invalid URL format'],
            ]);
        }

        // Require HTTPS in production
        if (app()->environment('production') && $parsed['scheme'] !== 'https') {
            throw ValidationException::withMessages([
                'url' => ['HTTPS is required for webhook URLs in production'],
            ]);
        }

        // Block localhost
        $blockedHosts = ['localhost', '127.0.0.1', '::1', '0.0.0.0'];
        if (in_array($parsed['host'], $blockedHosts)) {
            throw ValidationException::withMessages([
                'url' => ['Localhost webhooks are not allowed'],
            ]);
        }

        // Block credentials in URL
        if (isset($parsed['user']) || isset($parsed['pass'])) {
            throw ValidationException::withMessages([
                'url' => ['URLs with credentials are not allowed'],
            ]);
        }

        // Resolve to IP and check private ranges
        if (app()->environment('production')) {
            $ip = @gethostbyname($parsed['host']);

            if ($ip !== $parsed['host']) { // Successfully resolved
                $isPublic = filter_var(
                    $ip,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                );

                if ($isPublic === false) {
                    throw ValidationException::withMessages([
                        'url' => ['Private IP addresses are not allowed for webhooks'],
                    ]);
                }
            }
        }
    }

    /**
     * Check if webhook should be auto-disabled due to failures
     */
    public function checkAutoDisable(Webhook $webhook): bool
    {
        if ($webhook->shouldAutoDisable() && $webhook->is_active) {
            $this->disableWebhook($webhook);

            $this->logAction('webhook_auto_disabled', [
                'webhook_id' => $webhook->id,
                'organization_id' => $webhook->organization_id,
                'failure_count' => $webhook->failure_count,
            ]);

            return true;
        }

        return false;
    }
}
