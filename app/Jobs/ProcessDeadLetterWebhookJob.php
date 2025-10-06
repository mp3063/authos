<?php

namespace App\Jobs;

use App\Enums\WebhookDeliveryStatus;
use App\Models\WebhookDelivery;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ProcessDeadLetterWebhookJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 1;

    /**
     * Create a new job instance.
     */
    public function __construct(
        public WebhookDelivery $delivery
    ) {
        $this->onQueue('webhook_deadletter');
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        try {
            // Check if delivery still exists
            if (! $this->delivery->exists) {
                Log::warning('Webhook delivery not found in dead letter queue', [
                    'delivery_id' => $this->delivery->id,
                ]);

                return;
            }

            $webhook = $this->delivery->webhook;

            // Mark delivery as permanently failed
            $this->delivery->update([
                'status' => WebhookDeliveryStatus::FAILED,
                'completed_at' => now(),
            ]);

            // Increment webhook failure counter
            $webhook->incrementFailureCount();

            Log::info('Webhook delivery moved to dead letter', [
                'delivery_id' => $this->delivery->id,
                'webhook_id' => $webhook->id,
                'attempts' => $this->delivery->attempt_number,
                'event_type' => $this->delivery->event_type,
            ]);

            // Check if webhook should be auto-disabled
            if ($webhook->shouldAutoDisable()) {
                $webhook->update(['is_active' => false]);

                Log::warning('Webhook auto-disabled due to excessive failures', [
                    'webhook_id' => $webhook->id,
                    'organization_id' => $webhook->organization_id,
                    'failure_count' => $webhook->failure_count,
                ]);

                // TODO: Send notification to organization admins
                // This would typically involve dispatching a notification job
                // or sending an email about the webhook being disabled
            }

        } catch (\Exception $e) {
            Log::error('Dead letter webhook processing failed', [
                'delivery_id' => $this->delivery->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::critical('Dead letter webhook job failed', [
            'delivery_id' => $this->delivery->id,
            'webhook_id' => $this->delivery->webhook_id,
            'error' => $exception->getMessage(),
        ]);

        // This is critical - the dead letter processor itself failed
        // In a production system, this should trigger alerts
    }
}
