<?php

namespace Tests\Unit\Services;

use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use App\Services\WebhookSignatureService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class WebhookDeliveryServiceTest extends TestCase
{
    private WebhookDeliveryService $service;

    private WebhookSignatureService $signatureService;

    private Organization $organization;

    private Webhook $webhook;

    protected function setUp(): void
    {
        parent::setUp();

        $this->signatureService = new WebhookSignatureService;
        $this->service = new WebhookDeliveryService($this->signatureService);
        $this->organization = Organization::factory()->create();
        $this->webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['url' => 'https://example.com/webhook']);
    }

    public function test_delivers_webhook_successfully(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = $this->service->deliver($this->webhook, $payload);

        $this->assertInstanceOf(WebhookDelivery::class, $delivery);
        $this->assertEquals($this->webhook->id, $delivery->webhook_id);
        $this->assertEquals('success', $delivery->status);
        $this->assertEquals(200, $delivery->response_status);
        $this->assertEquals(0, $delivery->attempt);
    }

    public function test_retries_on_failure(): void
    {
        Http::fake([
            'example.com/*' => Http::sequence()
                ->push(['status' => 'error'], 500)
                ->push(['status' => 'error'], 500)
                ->push(['status' => 'success'], 200),
        ]);

        Queue::fake();

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = $this->service->deliver($this->webhook, $payload);

        $this->assertEquals('failed', $delivery->status);
        $this->assertEquals(500, $delivery->response_status);

        // Verify retry job was queued
        Queue::assertPushed(\App\Jobs\RetryWebhookDeliveryJob::class);
    }

    public function test_exponential_backoff(): void
    {
        $delays = [];
        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $delays[] = $this->service->calculateBackoff($attempt);
        }

        // Verify exponential growth: each delay should be larger than the previous
        $this->assertGreaterThan($delays[0], $delays[1]);
        $this->assertGreaterThan($delays[1], $delays[2]);
        $this->assertGreaterThan($delays[2], $delays[3]);
        $this->assertGreaterThan($delays[3], $delays[4]);

        // First retry should be around 60 seconds (1 minute)
        $this->assertEqualsWithDelta(60, $delays[0], 10);

        // Fifth retry should be much longer
        $this->assertGreaterThan(300, $delays[4]);
    }

    public function test_no_retry_on_4xx_errors(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'bad request'], 400),
        ]);

        Queue::fake();

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = $this->service->deliver($this->webhook, $payload);

        $this->assertEquals('failed', $delivery->status);
        $this->assertEquals(400, $delivery->response_status);
        $this->assertFalse($delivery->will_retry);

        // No retry job should be queued for 4xx errors
        Queue::assertNotPushed(\App\Jobs\RetryWebhookDeliveryJob::class);
    }

    public function test_retries_on_5xx_errors(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 503),
        ]);

        Queue::fake();

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = $this->service->deliver($this->webhook, $payload);

        $this->assertEquals('failed', $delivery->status);
        $this->assertEquals(503, $delivery->response_status);
        $this->assertTrue($delivery->will_retry);

        // Retry job should be queued for 5xx errors
        Queue::assertPushed(\App\Jobs\RetryWebhookDeliveryJob::class);
    }

    public function test_moves_to_dead_letter_after_max_retries(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = WebhookDelivery::factory()
            ->for($this->webhook)
            ->create([
                'attempt' => 5, // Max retries
                'status' => 'failed',
            ]);

        $result = $this->service->retry($delivery);

        $this->assertEquals('dead_letter', $result->status);
        $this->assertFalse($result->will_retry);
        $this->assertNotNull($result->moved_to_dead_letter_at);
    }

    public function test_tracks_delivery_time(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200, [
                'X-Response-Time' => '50ms',
            ]),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = $this->service->deliver($this->webhook, $payload);

        $this->assertNotNull($delivery->response_time_ms);
        $this->assertGreaterThan(0, $delivery->response_time_ms);
    }

    public function test_includes_signature_headers(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->service->deliver($this->webhook, $payload);

        Http::assertSent(function ($request) {
            return $request->hasHeader('X-Webhook-Signature')
                && $request->hasHeader('X-Webhook-Timestamp')
                && $request->hasHeader('X-Webhook-Event')
                && $request->hasHeader('X-Webhook-Id');
        });
    }

    public function test_handles_network_timeout(): void
    {
        Http::fake(function () {
            throw new \Illuminate\Http\Client\ConnectionException('Connection timeout');
        });

        Queue::fake();

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $delivery = $this->service->deliver($this->webhook, $payload);

        $this->assertEquals('failed', $delivery->status);
        $this->assertStringContainsString('timeout', strtolower($delivery->error_message ?? ''));
        $this->assertTrue($delivery->will_retry);
    }

    public function test_increments_webhook_failure_counter(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $this->webhook->update(['consecutive_failures' => 0]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->service->deliver($this->webhook, $payload);

        $this->webhook->refresh();

        $this->assertEquals(1, $this->webhook->consecutive_failures);
    }

    public function test_resets_failure_counter_on_success(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $this->webhook->update(['consecutive_failures' => 5]);

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->service->deliver($this->webhook, $payload);

        $this->webhook->refresh();

        $this->assertEquals(0, $this->webhook->consecutive_failures);
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

        $payload = ['event' => 'user.created', 'data' => ['id' => 1]];

        $this->service->deliver($this->webhook, $payload);

        $this->webhook->refresh();
        $stats = $this->webhook->delivery_stats;

        $this->assertEquals(11, $stats['total_deliveries']);
        $this->assertEquals(10, $stats['successful_deliveries']);
    }
}
