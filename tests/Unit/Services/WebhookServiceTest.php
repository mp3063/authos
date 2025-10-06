<?php

namespace Tests\Unit\Services;

use App\Models\Organization;
use App\Models\Webhook;
use App\Services\WebhookService;
use App\Services\WebhookSignatureService;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class WebhookServiceTest extends TestCase
{
    private WebhookService $service;

    private WebhookSignatureService $signatureService;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->signatureService = new WebhookSignatureService;
        $this->service = new WebhookService($this->signatureService);
        $this->organization = Organization::factory()->create();
    }

    public function test_creates_webhook(): void
    {
        $data = [
            'url' => 'https://example.com/webhook',
            'events' => ['user.created', 'user.updated'],
            'description' => 'Test webhook',
        ];

        $webhook = $this->service->createWebhook($this->organization, $data);

        $this->assertInstanceOf(Webhook::class, $webhook);
        $this->assertEquals($this->organization->id, $webhook->organization_id);
        $this->assertEquals('https://example.com/webhook', $webhook->url);
        $this->assertEquals(['user.created', 'user.updated'], $webhook->events);
        $this->assertNotEmpty($webhook->secret);
        $this->assertTrue($webhook->is_active);
    }

    public function test_validates_https_url(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Webhook URL must use HTTPS');

        $data = [
            'url' => 'http://example.com/webhook',
            'events' => ['user.created'],
        ];

        $this->service->createWebhook($this->organization, $data);
    }

    public function test_blocks_localhost_in_production(): void
    {
        config(['app.env' => 'production']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Localhost URLs are not allowed in production');

        $data = [
            'url' => 'https://localhost/webhook',
            'events' => ['user.created'],
        ];

        $this->service->createWebhook($this->organization, $data);
    }

    public function test_allows_localhost_in_local_environment(): void
    {
        config(['app.env' => 'local']);

        $data = [
            'url' => 'https://localhost/webhook',
            'events' => ['user.created'],
        ];

        $webhook = $this->service->createWebhook($this->organization, $data);

        $this->assertInstanceOf(Webhook::class, $webhook);
        $this->assertEquals('https://localhost/webhook', $webhook->url);
    }

    public function test_blocks_private_ips(): void
    {
        config(['app.env' => 'production']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Private IP addresses are not allowed');

        $data = [
            'url' => 'https://192.168.1.1/webhook',
            'events' => ['user.created'],
        ];

        $this->service->createWebhook($this->organization, $data);
    }

    public function test_rotates_secret(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['secret' => 'old_secret']);

        $oldSecret = $webhook->secret;

        $newWebhook = $this->service->rotateSecret($webhook);

        $this->assertNotEquals($oldSecret, $newWebhook->secret);
        $this->assertNotEmpty($newWebhook->secret);
    }

    public function test_calculates_success_rate(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'delivery_stats' => [
                    'total_deliveries' => 100,
                    'successful_deliveries' => 95,
                    'failed_deliveries' => 5,
                ],
            ]);

        $successRate = $this->service->calculateSuccessRate($webhook);

        $this->assertEquals(95.0, $successRate);
    }

    public function test_calculates_success_rate_with_no_deliveries(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'delivery_stats' => [
                    'total_deliveries' => 0,
                    'successful_deliveries' => 0,
                    'failed_deliveries' => 0,
                ],
            ]);

        $successRate = $this->service->calculateSuccessRate($webhook);

        $this->assertEquals(0.0, $successRate);
    }

    public function test_test_webhook(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'success'], 200),
        ]);

        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['url' => 'https://example.com/webhook']);

        $result = $this->service->testWebhook($webhook);

        $this->assertTrue($result['success']);
        $this->assertEquals(200, $result['status_code']);
        Http::assertSent(function ($request) {
            return $request->url() === 'https://example.com/webhook'
                && $request->hasHeader('X-Webhook-Signature')
                && $request->hasHeader('X-Webhook-Timestamp');
        });
    }

    public function test_auto_disables_after_max_failures(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'consecutive_failures' => 10,
                'is_active' => true,
            ]);

        $this->service->checkAndDisableWebhook($webhook);

        $webhook->refresh();

        $this->assertFalse($webhook->is_active);
        $this->assertNotNull($webhook->disabled_at);
    }

    public function test_does_not_disable_webhook_with_few_failures(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'consecutive_failures' => 3,
                'is_active' => true,
            ]);

        $this->service->checkAndDisableWebhook($webhook);

        $webhook->refresh();

        $this->assertTrue($webhook->is_active);
        $this->assertNull($webhook->disabled_at);
    }

    public function test_updates_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'url' => 'https://old.example.com/webhook',
                'events' => ['user.created'],
            ]);

        $data = [
            'url' => 'https://new.example.com/webhook',
            'events' => ['user.created', 'user.updated'],
            'description' => 'Updated webhook',
        ];

        $updatedWebhook = $this->service->updateWebhook($webhook, $data);

        $this->assertEquals('https://new.example.com/webhook', $updatedWebhook->url);
        $this->assertEquals(['user.created', 'user.updated'], $updatedWebhook->events);
        $this->assertEquals('Updated webhook', $updatedWebhook->description);
    }

    public function test_enables_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'is_active' => false,
                'disabled_at' => now(),
            ]);

        $enabledWebhook = $this->service->enableWebhook($webhook);

        $this->assertTrue($enabledWebhook->is_active);
        $this->assertNull($enabledWebhook->disabled_at);
        $this->assertEquals(0, $enabledWebhook->consecutive_failures);
    }

    public function test_disables_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['is_active' => true]);

        $disabledWebhook = $this->service->disableWebhook($webhook);

        $this->assertFalse($disabledWebhook->is_active);
        $this->assertNotNull($disabledWebhook->disabled_at);
    }

    public function test_deletes_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create();

        $this->service->deleteWebhook($webhook);

        $this->assertDatabaseMissing('webhooks', ['id' => $webhook->id]);
    }
}
