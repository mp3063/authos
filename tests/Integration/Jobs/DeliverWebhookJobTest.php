<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\DeliverWebhookJob;
use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class DeliverWebhookJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private Webhook $webhook;

    private WebhookDelivery $delivery;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook',
            'events' => ['user.created'],
            'is_active' => true,
        ]);

        $this->delivery = WebhookDelivery::factory()->create([
            'webhook_id' => $this->webhook->id,
            'event_type' => 'user.created',
            'payload' => ['user_id' => 1, 'email' => 'test@example.com'],
            'status' => 'pending',
        ]);
    }

    #[Test]
    public function job_can_be_dispatched_with_webhook_delivery(): void
    {
        Queue::fake();

        DeliverWebhookJob::dispatch($this->delivery);

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->delivery->id === $this->delivery->id;
        });
    }

    #[Test]
    public function job_sends_http_request_to_webhook_url(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['success' => true], 200),
        ]);

        $mockService = Mockery::mock(WebhookDeliveryService::class);
        $mockService->shouldReceive('deliver')
            ->once()
            ->with($this->delivery)
            ->andReturnUsing(function ($delivery) {
                $delivery->update([
                    'status' => 'success',
                    'http_status_code' => 200,
                    'response_body' => json_encode(['success' => true]),
                    'completed_at' => now(),
                ]);
                return true;
            });

        $this->app->instance(WebhookDeliveryService::class, $mockService);

        $job = new DeliverWebhookJob($this->delivery);
        $job->handle($mockService);

        $this->delivery->refresh();
        $this->assertEquals('success', $this->delivery->status->value);
    }

    #[Test]
    public function job_records_response_status_and_body(): void
    {
        $mockService = Mockery::mock(WebhookDeliveryService::class);
        $mockService->shouldReceive('deliver')
            ->once()
            ->andReturnUsing(function ($delivery) {
                $delivery->update([
                    'status' => 'success',
                    'http_status_code' => 200,
                    'response_body' => json_encode(['success' => true, 'message' => 'Received']),
                    'completed_at' => now(),
                ]);
                return true;
            });

        $this->app->instance(WebhookDeliveryService::class, $mockService);

        $job = new DeliverWebhookJob($this->delivery);
        $job->handle($mockService);

        $this->delivery->refresh();
        $this->assertEquals(200, $this->delivery->http_status_code);
        $this->assertNotNull($this->delivery->response_body);

        $responseData = json_decode($this->delivery->response_body, true);
        $this->assertTrue($responseData['success']);
        $this->assertEquals('Received', $responseData['message']);
    }

    #[Test]
    public function job_handles_timeouts_based_on_webhook_configuration(): void
    {
        $this->webhook->update(['timeout' => 5]);

        $mockService = Mockery::mock(WebhookDeliveryService::class);
        $mockService->shouldReceive('deliver')
            ->once()
            ->andThrow(new \Exception('Request timeout after 5 seconds'));

        $this->app->instance(WebhookDeliveryService::class, $mockService);

        Log::shouldReceive('error')
            ->once()
            ->with(
                'Webhook delivery job failed',
                Mockery::on(function ($context) {
                    return isset($context['error']) &&
                           str_contains($context['error'], 'timeout');
                })
            );

        $job = new DeliverWebhookJob($this->delivery);

        try {
            $job->handle($mockService);
            $this->fail('Expected exception was not thrown');
        } catch (\Exception $e) {
            $this->assertStringContainsString('timeout', $e->getMessage());
        }

        $this->delivery->refresh();
        $this->assertEquals('failed', $this->delivery->status->value);
    }

    #[Test]
    public function job_handles_ssl_errors(): void
    {
        $mockService = Mockery::mock(WebhookDeliveryService::class);
        $mockService->shouldReceive('deliver')
            ->once()
            ->andThrow(new \Exception('SSL certificate verification failed'));

        $this->app->instance(WebhookDeliveryService::class, $mockService);

        Log::shouldReceive('error')
            ->once()
            ->with(
                'Webhook delivery job failed',
                Mockery::on(function ($context) {
                    return isset($context['error']) &&
                           str_contains($context['error'], 'SSL');
                })
            );

        $job = new DeliverWebhookJob($this->delivery);

        try {
            $job->handle($mockService);
            $this->fail('Expected exception was not thrown');
        } catch (\Exception $e) {
            $this->assertStringContainsString('SSL', $e->getMessage());
        }

        $this->delivery->refresh();
        $this->assertEquals('failed', $this->delivery->status->value);
    }

    #[Test]
    public function job_updates_delivery_status_correctly(): void
    {
        $mockService = Mockery::mock(WebhookDeliveryService::class);
        $mockService->shouldReceive('deliver')
            ->once()
            ->andReturnUsing(function ($delivery) {
                $delivery->update([
                    'status' => 'success',
                    'http_status_code' => 200,
                    'response_body' => '{"success":true}',
                    'completed_at' => now(),
                    'attempt_number' => 1,
                ]);
                return true;
            });

        $this->app->instance(WebhookDeliveryService::class, $mockService);

        $this->assertEquals('pending', $this->delivery->status->value);
        $this->assertEquals(1, $this->delivery->attempt_number);

        $job = new DeliverWebhookJob($this->delivery);
        $job->handle($mockService);

        $this->delivery->refresh();
        $this->assertEquals('success', $this->delivery->status->value);
        $this->assertEquals(1, $this->delivery->attempt_number);
        $this->assertNotNull($this->delivery->completed_at);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
