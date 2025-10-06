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

class DeliverWebhookJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 1;

    /**
     * The maximum number of unhandled exceptions to allow before failing.
     */
    public int $maxExceptions = 3;

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
        $this->onQueue('webhook_delivery');
    }

    /**
     * Execute the job.
     */
    public function handle(WebhookDeliveryService $deliveryService): void
    {
        try {
            // Check if delivery still exists and is in a valid state
            if (! $this->delivery->exists) {
                Log::warning('Webhook delivery not found', [
                    'delivery_id' => $this->delivery->id,
                ]);

                return;
            }

            // Attempt delivery
            $deliveryService->deliver($this->delivery);

        } catch (\Exception $e) {
            Log::error('Webhook delivery job failed', [
                'delivery_id' => $this->delivery->id,
                'webhook_id' => $this->delivery->webhook_id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            // Mark delivery as failed
            $this->delivery->markAsFailed(500, $e->getMessage());

            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Webhook delivery job permanently failed', [
            'delivery_id' => $this->delivery->id,
            'webhook_id' => $this->delivery->webhook_id,
            'error' => $exception->getMessage(),
        ]);

        // Ensure delivery is marked as failed
        if ($this->delivery->exists) {
            $this->delivery->markAsFailed(500, 'Job failed: '.$exception->getMessage());
        }
    }
}
