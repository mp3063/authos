<?php

namespace Tests\Integration;

use App\Events\UserCreatedEvent;
use App\Jobs\DeliverWebhookJob;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Services\WebhookDeliveryService;
use App\Services\WebhookSignatureService;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class WebhookIntegrationTest extends TestCase
{
    private Organization $organization;

    private Webhook $webhook;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'url' => 'https://example.com/webhook',
                'events' => ['*'],
            ]);
    }

    public function test_end_to_end_webhook_delivery(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        Queue::fake();

        // Create user, which should trigger webhook
        $user = User::factory()->for($this->organization)->create();
        Event::dispatch(new UserCreatedEvent($user));

        // Assert webhook job was queued
        Queue::assertPushed(DeliverWebhookJob::class);

        // Process the job
        $job = Queue::pushedJobs()[DeliverWebhookJob::class][0]['job'];
        $job->handle(new WebhookDeliveryService(new WebhookSignatureService));

        // Verify delivery was created
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $this->webhook->id,
            'status' => 'success',
        ]);

        // Verify HTTP request was made
        Http::assertSent(function ($request) {
            return $request->url() === 'https://example.com/webhook'
                && $request->hasHeader('X-Webhook-Signature')
                && $request->hasHeader('X-Webhook-Event');
        });
    }

    public function test_webhook_retry_flow(): void
    {
        Http::fake([
            'example.com/*' => Http::sequence()
                ->push(['error' => 'server error'], 500)
                ->push(['error' => 'server error'], 500)
                ->push(['status' => 'received'], 200),
        ]);

        $deliveryService = new WebhookDeliveryService(new WebhookSignatureService);

        // Initial delivery fails
        $delivery = $deliveryService->deliver($this->webhook, [
            'event' => 'user.created',
            'data' => ['id' => 1],
        ]);

        $this->assertEquals('failed', $delivery->status);
        $this->assertTrue($delivery->will_retry);

        // First retry fails
        $delivery = $deliveryService->retry($delivery);
        $this->assertEquals('failed', $delivery->status);

        // Second retry succeeds
        $delivery = $deliveryService->retry($delivery);
        $this->assertEquals('success', $delivery->status);

        $this->assertEquals(2, $delivery->attempt);
    }

    public function test_webhook_signature_verification(): void
    {
        $signatureService = new WebhookSignatureService;
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $timestamp = time();

        $signature = $signatureService->generateSignature($payload, $this->webhook->secret, $timestamp);

        // Verify valid signature
        $isValid = $signatureService->verifySignature(
            $payload,
            $signature,
            $this->webhook->secret,
            $timestamp
        );

        $this->assertTrue($isValid);

        // Verify invalid signature is rejected
        $isInvalid = $signatureService->verifySignature(
            $payload,
            'invalid-signature',
            $this->webhook->secret,
            $timestamp
        );

        $this->assertFalse($isInvalid);
    }

    public function test_multiple_webhooks_per_event(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
            'another.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        Queue::fake();

        // Create multiple webhooks
        $webhook2 = Webhook::factory()
            ->for($this->organization)
            ->create([
                'url' => 'https://another.com/webhook',
                'events' => ['user.created'],
            ]);

        // Create user
        $user = User::factory()->for($this->organization)->create();
        Event::dispatch(new UserCreatedEvent($user));

        // Both webhooks should receive the event
        Queue::assertPushed(DeliverWebhookJob::class, 2);
    }

    public function test_webhook_auto_disable_after_failures(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['error' => 'server error'], 500),
        ]);

        $deliveryService = new WebhookDeliveryService(new WebhookSignatureService);

        $this->webhook->update(['consecutive_failures' => 0]);

        // Trigger 10 consecutive failures
        for ($i = 0; $i < 10; $i++) {
            $deliveryService->deliver($this->webhook, [
                'event' => 'user.created',
                'data' => ['id' => $i],
            ]);
            $this->webhook->refresh();
        }

        $this->assertFalse($this->webhook->is_active);
        $this->assertEquals(10, $this->webhook->consecutive_failures);
        $this->assertNotNull($this->webhook->disabled_at);
    }

    public function test_webhook_re_enable_after_auto_disable(): void
    {
        $this->webhook->update([
            'is_active' => false,
            'disabled_at' => now(),
            'consecutive_failures' => 10,
        ]);

        // Re-enable webhook
        $this->webhook->enable();
        $this->webhook->refresh();

        $this->assertTrue($this->webhook->is_active);
        $this->assertNull($this->webhook->disabled_at);
        $this->assertEquals(0, $this->webhook->consecutive_failures);

        // Verify it can receive events again
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $deliveryService = new WebhookDeliveryService(new WebhookSignatureService);
        $delivery = $deliveryService->deliver($this->webhook, [
            'event' => 'user.created',
            'data' => ['id' => 1],
        ]);

        $this->assertEquals('success', $delivery->status);
    }

    public function test_webhook_delivery_statistics(): void
    {
        Http::fake([
            'example.com/*' => Http::sequence()
                ->push(['status' => 'received'], 200)
                ->push(['status' => 'received'], 200)
                ->push(['error' => 'error'], 500)
                ->push(['status' => 'received'], 200),
        ]);

        $deliveryService = new WebhookDeliveryService(new WebhookSignatureService);

        $this->webhook->update([
            'delivery_stats' => [
                'total_deliveries' => 0,
                'successful_deliveries' => 0,
                'failed_deliveries' => 0,
                'average_response_time_ms' => 0,
            ],
        ]);

        // Make 4 deliveries
        for ($i = 0; $i < 4; $i++) {
            $deliveryService->deliver($this->webhook, [
                'event' => 'test.event',
                'data' => ['id' => $i],
            ]);
        }

        $this->webhook->refresh();
        $stats = $this->webhook->delivery_stats;

        $this->assertEquals(4, $stats['total_deliveries']);
        $this->assertEquals(3, $stats['successful_deliveries']);
        $this->assertEquals(1, $stats['failed_deliveries']);
        $this->assertGreaterThan(0, $stats['average_response_time_ms']);
    }

    public function test_webhook_delivery_respects_organization_isolation(): void
    {
        $org2 = Organization::factory()->create();
        $webhook2 = Webhook::factory()
            ->for($org2)
            ->create(['events' => ['*']]);

        Queue::fake();

        // Create user in org1
        $user = User::factory()->for($this->organization)->create();
        Event::dispatch(new UserCreatedEvent($user));

        // Only webhook from org1 should be triggered
        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->webhook->organization_id === $this->organization->id;
        });

        Queue::assertPushed(DeliverWebhookJob::class, 1);
    }

    public function test_webhook_payload_excludes_sensitive_data(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'received'], 200),
        ]);

        $deliveryService = new WebhookDeliveryService(new WebhookSignatureService);

        $user = User::factory()->for($this->organization)->create([
            'password' => bcrypt('secret'),
            'two_factor_secret' => 'mfa-secret',
        ]);

        $delivery = $deliveryService->deliver($this->webhook, [
            'event' => 'user.created',
            'data' => $user->toArray(),
        ]);

        $payload = json_decode($delivery->payload, true);

        $this->assertArrayNotHasKey('password', $payload['data']);
        $this->assertArrayNotHasKey('two_factor_secret', $payload['data']);
        $this->assertArrayNotHasKey('remember_token', $payload['data']);
    }
}
