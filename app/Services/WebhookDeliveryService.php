<?php

namespace App\Services;

use App\Enums\WebhookDeliveryStatus;
use App\Jobs\DeliverWebhookJob;
use App\Jobs\RetryWebhookDeliveryJob;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;

class WebhookDeliveryService extends BaseService
{
    public function __construct(
        protected WebhookSignatureService $signatureService
    ) {}

    /**
     * Deliver a webhook
     */
    public function deliver(WebhookDelivery $delivery): bool
    {
        try {
            $webhook = $delivery->webhook;

            // Check if webhook is still active
            if (! $webhook->is_active) {
                $this->logAction('webhook_delivery_skipped_inactive', [
                    'delivery_id' => $delivery->id,
                    'webhook_id' => $webhook->id,
                ]);

                return false;
            }

            // Mark as sending
            $delivery->markAsSending();

            // Generate signature
            $timestamp = time();
            $payloadJson = json_encode($delivery->payload);
            $signature = $this->signatureService->generateSignature(
                $payloadJson,
                $webhook->decrypted_secret,
                $timestamp
            );

            // Store signature
            $delivery->update(['signature' => $signature]);

            // Build headers
            $headers = $this->signatureService->buildHeaders($delivery, $signature, $timestamp);

            // Send HTTP request with timeout
            $startTime = microtime(true);

            $response = Http::timeout($webhook->timeout_seconds)
                ->withHeaders($headers)
                ->post($webhook->url, $delivery->payload);

            $durationMs = (int) ((microtime(true) - $startTime) * 1000);

            // Check if successful (2xx status code)
            if ($response->successful()) {
                $this->markSuccess($delivery, $response, $durationMs);
                $webhook->resetFailureCount();

                return true;
            }

            // Failed response
            $this->handleFailure($delivery, $response->status(), $response->body(), $durationMs);

            return false;

        } catch (ConnectionException $e) {
            $this->handleException($e, 'webhook_delivery', [
                'delivery_id' => $delivery->id,
                'webhook_id' => $delivery->webhook_id,
            ]);

            $this->handleFailure($delivery, 0, $e->getMessage());

            return false;

        } catch (RequestException $e) {
            $this->handleException($e, 'webhook_delivery', [
                'delivery_id' => $delivery->id,
                'webhook_id' => $delivery->webhook_id,
            ]);

            $this->handleFailure($delivery, $e->getCode(), $e->getMessage());

            return false;

        } catch (\Exception $e) {
            $this->handleException($e, 'webhook_delivery', [
                'delivery_id' => $delivery->id,
                'webhook_id' => $delivery->webhook_id,
            ]);

            $this->handleFailure($delivery, 500, $e->getMessage());

            return false;
        }
    }

    /**
     * Mark delivery as successful
     */
    protected function markSuccess($delivery, $response, int $durationMs): void
    {
        $delivery->markAsSuccess(
            $response->status(),
            $response->body(),
            $response->headers(),
            $durationMs
        );

        $this->logAction('webhook_delivery_success', [
            'delivery_id' => $delivery->id,
            'webhook_id' => $delivery->webhook_id,
            'duration_ms' => $durationMs,
        ]);
    }

    /**
     * Handle delivery failure
     */
    protected function handleFailure(
        WebhookDelivery $delivery,
        int $httpStatus,
        string $error,
        ?int $durationMs = null
    ): void {
        $webhook = $delivery->webhook;

        // Check if we should retry
        if ($this->shouldRetry($delivery, $httpStatus)) {
            $this->scheduleRetry($delivery);
        } else {
            // Mark as permanently failed
            $delivery->markAsFailed($httpStatus, $error);
            $webhook->incrementFailureCount();

            $this->logAction('webhook_delivery_failed', [
                'delivery_id' => $delivery->id,
                'webhook_id' => $webhook->id,
                'http_status' => $httpStatus,
                'error' => $error,
            ]);

            // Check if webhook should be auto-disabled
            if ($webhook->shouldAutoDisable()) {
                $webhook->update(['is_active' => false]);

                $this->logAction('webhook_auto_disabled', [
                    'webhook_id' => $webhook->id,
                    'failure_count' => $webhook->failure_count,
                ]);
            }
        }
    }

    /**
     * Determine if delivery should be retried
     */
    protected function shouldRetry(WebhookDelivery $delivery, int $httpStatus): bool
    {
        // Don't retry if max attempts reached
        if ($delivery->hasReachedMaxAttempts()) {
            return false;
        }

        // Retry on network errors (0), timeouts (408), rate limits (429), and server errors (5xx)
        $retryableStatuses = [0, 408, 429, 500, 502, 503, 504];

        return in_array($httpStatus, $retryableStatuses) || $httpStatus >= 500;
    }

    /**
     * Schedule delivery retry
     */
    public function scheduleRetry(WebhookDelivery $delivery): void
    {
        $delayMinutes = $delivery->getRetryDelay();

        $delivery->scheduleRetry($delayMinutes);

        $this->logAction('webhook_delivery_retry_scheduled', [
            'delivery_id' => $delivery->id,
            'webhook_id' => $delivery->webhook_id,
            'attempt_number' => $delivery->attempt_number,
            'next_retry_at' => $delivery->next_retry_at,
            'delay_minutes' => $delayMinutes,
        ]);

        // Dispatch retry job
        RetryWebhookDeliveryJob::dispatch($delivery)
            ->delay(now()->addMinutes($delayMinutes));
    }

    /**
     * Move delivery to dead letter queue
     */
    public function moveToDeadLetter(WebhookDelivery $delivery): void
    {
        $delivery->update([
            'status' => WebhookDeliveryStatus::FAILED,
            'completed_at' => now(),
        ]);

        $this->logAction('webhook_delivery_dead_letter', [
            'delivery_id' => $delivery->id,
            'webhook_id' => $delivery->webhook_id,
            'attempt_number' => $delivery->attempt_number,
        ]);

        // TODO: Send notification to organization admins
    }

    /**
     * Get delivery history for a webhook
     */
    public function getDeliveryHistory(Webhook $webhook, int $limit = 50): Collection
    {
        return WebhookDelivery::where('webhook_id', $webhook->id)
            ->latest()
            ->limit($limit)
            ->get();
    }

    /**
     * Get retryable deliveries
     */
    public function getRetryableDeliveries(): Collection
    {
        return WebhookDelivery::retryable()->get();
    }

    /**
     * Requeue failed delivery
     */
    public function requeueFailedDelivery(WebhookDelivery $delivery): void
    {
        if (! $delivery->canRetry()) {
            $this->logAction('webhook_delivery_requeue_failed', [
                'delivery_id' => $delivery->id,
                'reason' => 'max_attempts_reached',
            ]);

            return;
        }

        $delivery->update([
            'status' => WebhookDeliveryStatus::PENDING,
        ]);

        DeliverWebhookJob::dispatch($delivery);

        $this->logAction('webhook_delivery_requeued', [
            'delivery_id' => $delivery->id,
            'webhook_id' => $delivery->webhook_id,
        ]);
    }
}
