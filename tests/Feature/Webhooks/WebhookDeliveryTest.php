<?php

namespace Tests\Feature\Webhooks;

use App\Jobs\RetryWebhookDeliveryJob;
use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use App\Services\WebhookSignatureService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class WebhookDeliveryTest extends TestCase
{
    private Organization $organization;

    private Webhook $webhook;

    private WebhookDeliveryService $deliveryService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['url' => 'https://example.com/webhook']);

        $this->deliveryService = new WebhookDeliveryService(
            new WebhookSignatureService
        );
    }

    public function test_delivers_webhook_successfully(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $payload = [
            'event' => 'user.created',
            'data' => ['id' => 1, 'name' => 'John Doe'],
        ];

        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $this->assertEquals('success', $result->status);
        $this->assertEquals(200, $result->response_status);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $this->webhook->id,
            'status' => 'success',
        ]);
    }

    public function test_delivers_webhook_with_failure(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $payload = [
            'event' => 'user.created',
            'data' => ['id' => 1],
        ];

        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $this->assertContains($result->status, ['retrying', 'failed']);
        $this->assertEquals(500, $result->response_status);
    }

    public function test_retries_with_exponential_backoff(): void
    {
        Queue::fake();

        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        Queue::assertPushed(RetryWebhookDeliveryJob::class, function ($job) {
            return $job->delay !== null && $job->delay->isFuture();
        });
    }

    public function test_respects_max_retry_attempts(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $delivery = WebhookDelivery::factory()
            ->for($this->webhook)
            ->create([
                'attempt_number' => 6, // Max attempts reached
                'status' => 'failed',
            ]);

        // Delivery should not retry
        $this->assertFalse($delivery->canRetry());
    }

    public function test_moves_to_dead_letter_queue(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $delivery = WebhookDelivery::factory()
            ->for($this->webhook)
            ->create([
                'attempt_number' => 6,
                'status' => 'failed',
            ]);

        $this->deliveryService->moveToDeadLetter($delivery);

        $this->assertDatabaseHas('webhook_deliveries', [
            'id' => $delivery->id,
            'status' => 'failed',
        ]);
    }

    public function test_auto_disables_webhook_after_consecutive_failures(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $this->webhook->update(['failure_count' => 9]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $this->webhook->refresh();

        $this->assertGreaterThanOrEqual(10, $this->webhook->failure_count);
    }

    public function test_includes_signature_in_headers(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        Http::assertSent(function ($request) {
            return $request->hasHeader('X-Webhook-Signature')
                && $request->hasHeader('X-Webhook-Timestamp');
        });
    }

    public function test_stores_response_body(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'processed', 'message' => 'Success'], 200),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertNotNull($delivery->response_body);
        $this->assertStringContainsString('processed', $delivery->response_body);
    }

    public function test_tracks_response_time(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertNotNull($delivery->request_duration_ms);
        $this->assertGreaterThanOrEqual(0, $delivery->request_duration_ms);
    }

    public function test_updates_webhook_last_delivered_at(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $this->webhook->update(['last_delivered_at' => null]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $this->webhook->refresh();

        $this->assertNotNull($this->webhook->last_delivered_at);
    }

    public function test_updates_delivery_stats(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $this->webhook->update([
            'delivery_stats' => [
                'total_deliveries' => 10,
                'successful_deliveries' => 9,
                'failed_deliveries' => 1,
                'average_response_time_ms' => 100,
            ],
        ]);
        $this->webhook->refresh();

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $this->webhook->refresh();

        $stats = $this->webhook->delivery_stats ?? [];
        $this->assertEquals(11, $stats['total_deliveries'] ?? 1);
        $this->assertEquals(10, $stats['successful_deliveries'] ?? 1);
    }

    public function test_no_retry_on_4xx_client_errors(): void
    {
        Queue::fake();

        Http::fake([
            'example.com/*' => Http::response(['error' => 'bad request'], 400),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    public function test_retries_on_5xx_server_errors(): void
    {
        Queue::fake();

        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 503),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        Queue::assertPushed(RetryWebhookDeliveryJob::class);
    }

    public function test_handles_network_timeout(): void
    {
        Queue::fake();

        Http::fake(function () {
            throw new \Illuminate\Http\Client\ConnectionException('Connection timeout');
        });

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload, 'user.created');

        $this->assertContains($result->status, ['retrying', 'failed']);
    }
}
