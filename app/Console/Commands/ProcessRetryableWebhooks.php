<?php

namespace App\Console\Commands;

use App\Jobs\RetryWebhookDeliveryJob;
use App\Models\WebhookDelivery;
use Illuminate\Console\Command;

class ProcessRetryableWebhooks extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'webhooks:process-retries
                            {--limit=100 : Maximum number of retries to process}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Process webhook deliveries that are ready for retry';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $limit = (int) $this->option('limit');

        $this->info('Processing retryable webhook deliveries...');

        // Get deliveries that are ready to retry
        $deliveries = WebhookDelivery::retryable()
            ->limit($limit)
            ->get();

        if ($deliveries->isEmpty()) {
            $this->info('No webhook deliveries ready for retry.');

            return self::SUCCESS;
        }

        $this->info("Found {$deliveries->count()} deliveries to retry.");

        $processed = 0;

        foreach ($deliveries as $delivery) {
            try {
                // Dispatch retry job immediately
                RetryWebhookDeliveryJob::dispatch($delivery);

                $processed++;

                $this->line("Queued retry for delivery #{$delivery->id} (webhook #{$delivery->webhook_id}, attempt {$delivery->attempt_number})");
            } catch (\Exception $e) {
                $this->error("Failed to queue retry for delivery #{$delivery->id}: {$e->getMessage()}");
            }
        }

        $this->info("Successfully queued {$processed} webhook retries.");

        return self::SUCCESS;
    }
}
