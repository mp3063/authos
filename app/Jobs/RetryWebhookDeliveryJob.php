<?php

namespace App\Jobs;

use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RetryWebhookDeliveryJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 1;

    /**
     * The number of seconds the job can run before timing out.
     */
    public int $timeout = 60;

    /**
     * Create a new job instance.
     */
    public function __construct(
        public WebhookDelivery $delivery
    ) {
        $this->onQueue('webhook_retry');
    }

    /**
     * Execute the job.
     */
    public function handle(WebhookDeliveryService $deliveryService): void
    {
        try {
            // Check if delivery still exists
            if (! $this->delivery->exists) {
                Log::warning('Webhook delivery not found for retry', [
                    'delivery_id' => $this->delivery->id,
                ]);

                return;
            }

            // Check if webhook is still active
            $webhook = $this->delivery->webhook;
            if (! $webhook || ! $webhook->is_active) {
                Log::info('Webhook inactive, skipping retry', [
                    'delivery_id' => $this->delivery->id,
                    'webhook_id' => $webhook?->id,
                ]);

                return;
            }

            // Check if max attempts reached
            if ($this->delivery->hasReachedMaxAttempts()) {
                Log::info('Max retry attempts reached, moving to dead letter', [
                    'delivery_id' => $this->delivery->id,
                    'webhook_id' => $webhook->id,
                    'attempts' => $this->delivery->attempt_number,
                ]);

                // Move to dead letter queue
                ProcessDeadLetterWebhookJob::dispatch($this->delivery)
                    ->onQueue('webhook_deadletter');

                return;
            }

            // Attempt delivery
            $success = $deliveryService->deliver($this->delivery);

            if (! $success) {
                // Delivery failed, schedule next retry if possible
                if ($this->delivery->canRetry()) {
                    $deliveryService->scheduleRetry($this->delivery);
                } else {
                    // Move to dead letter queue
                    ProcessDeadLetterWebhookJob::dispatch($this->delivery)
                        ->onQueue('webhook_deadletter');
                }
            }

        } catch (\Exception $e) {
            Log::error('Webhook retry job failed', [
                'delivery_id' => $this->delivery->id,
                'webhook_id' => $this->delivery->webhook_id,
                'attempt' => $this->delivery->attempt_number,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Webhook retry job permanently failed', [
            'delivery_id' => $this->delivery->id,
            'webhook_id' => $this->delivery->webhook_id,
            'error' => $exception->getMessage(),
        ]);

        // Move to dead letter queue
        if ($this->delivery->exists) {
            ProcessDeadLetterWebhookJob::dispatch($this->delivery)
                ->onQueue('webhook_deadletter');
        }
    }
}
