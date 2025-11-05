<?php

namespace Tests\Integration\Webhooks;

use App\Enums\WebhookDeliveryStatus;
use App\Jobs\RetryWebhookDeliveryJob;
use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Services\WebhookDeliveryService;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Webhook Retry Flow
 *
 * Tests the comprehensive retry mechanism for failed webhook deliveries including:
 * - Exponential backoff calculation (1min → 5min → 15min → 1hr → 6hr → 24hr)
 * - HTTP status-based retry logic (timeouts, 408, 429, 5xx)
 * - No retry on success (2xx) or most client errors (4xx except 408/429)
 * - Max 6 attempts enforcement
 * - Retry job scheduling with correct delays
 * - Success after retry scenarios
 * - Retry counter incrementation
 * - Permanent failure after max retries
 *
 * Key behaviors tested:
 * - Retryable statuses: 0 (timeout), 408, 429, 500, 502, 503, 504
 * - Non-retryable statuses: 2xx (success), 400, 401, 403, 404 (client errors)
 * - Exponential backoff delays: [1, 5, 15, 60, 360, 1440] minutes
 * - RetryWebhookDeliveryJob dispatched with correct delay
 * - Status transitions: PENDING → RETRYING → SUCCESS/FAILED
 * - attempt_number increments on each retry
 * - next_retry_at calculated using getRetryDelay()
 *
 * @see WebhookDeliveryFlowTest For basic delivery flow tests
 * @see WebhookDelivery::getRetryDelay() For exponential backoff calculation
 * @see WebhookDeliveryService::shouldRetry() For retry decision logic
 * @see WebhookDeliveryService::scheduleRetry() For retry scheduling
 */
#[Group('webhooks')]
#[Group('integration')]
class WebhookRetryFlowTest extends IntegrationTestCase
{
    protected Organization $organization;

    protected Webhook $webhook;

    protected WebhookDeliveryService $deliveryService;

    protected function setUp(): void
    {
        parent::setUp();

        // Create organization and webhook
        $this->organization = $this->createOrganization(['name' => 'Retry Test Org']);

        $this->webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook',
            'secret' => 'test-secret-key',
            'timeout_seconds' => 30,
            'is_active' => true,
            'events' => ['user.created'],
        ]);

        $this->deliveryService = app(WebhookDeliveryService::class);
    }

    // ============================================================
    // EXPONENTIAL BACKOFF CALCULATION
    // ============================================================

    #[Test]
    public function exponential_backoff_calculation_follows_expected_delays()
    {
        // ARRANGE: Create delivery at different attempt numbers
        $expectedDelays = [
            1 => 1,      // 1 minute
            2 => 5,      // 5 minutes
            3 => 15,     // 15 minutes
            4 => 60,     // 1 hour
            5 => 360,    // 6 hours
            6 => 1440,   // 24 hours
        ];

        foreach ($expectedDelays as $attemptNumber => $expectedDelayMinutes) {
            // ARRANGE: Create delivery at specific attempt number
            $delivery = WebhookDelivery::factory()->create([
                'webhook_id' => $this->webhook->id,
                'attempt_number' => $attemptNumber,
                'status' => WebhookDeliveryStatus::RETRYING,
            ]);

            // ACT: Calculate retry delay
            $actualDelay = $delivery->getRetryDelay();

            // ASSERT: Delay matches expected exponential backoff
            $this->assertEquals(
                $expectedDelayMinutes,
                $actualDelay,
                "Attempt {$attemptNumber} should have {$expectedDelayMinutes}min delay, got {$actualDelay}min"
            );
        }
    }

    // ============================================================
    // HTTP STATUS-BASED RETRY LOGIC: TIMEOUT/0
    // ============================================================

    #[Test]
    public function retry_triggered_on_connection_timeout()
    {
        // ARRANGE: Mock connection timeout (status 0)
        Http::fake([
            'example.com/*' => function () {
                throw new \Illuminate\Http\Client\ConnectionException('Connection timeout');
            },
        ]);

        Queue::fake();

        $payload = ['event' => 'user.created', 'data' => ['user_id' => 123]];

        // ACT: Attempt delivery (will timeout)
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(0, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
        $this->assertNotNull($delivery->next_retry_at);

        // ASSERT: Retry job scheduled with 1 minute delay (first attempt)
        Queue::assertPushed(RetryWebhookDeliveryJob::class, function ($job) use ($delivery) {
            // Job delay is a Carbon instance, check diffInMinutes from now
            $delayMinutes = abs(now()->diffInMinutes($job->delay));

            return $job->delivery->id === $delivery->id && $delayMinutes >= 0 && $delayMinutes <= 2; // Allow 1-2 min tolerance
        });
    }

    // ============================================================
    // HTTP STATUS-BASED RETRY LOGIC: 408
    // ============================================================

    #[Test]
    public function retry_triggered_on_408_request_timeout()
    {
        // ARRANGE: Mock 408 Request Timeout
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Request Timeout'], 408),
        ]);

        Queue::fake();

        $payload = ['event' => 'user.updated', 'data' => ['user_id' => 456]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(408, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
        $this->assertNotNull($delivery->next_retry_at);

        // ASSERT: Retry job scheduled
        Queue::assertPushed(RetryWebhookDeliveryJob::class, function ($job) use ($delivery) {
            return $job->delivery->id === $delivery->id;
        });
    }

    // ============================================================
    // HTTP STATUS-BASED RETRY LOGIC: 429
    // ============================================================

    #[Test]
    public function retry_triggered_on_429_too_many_requests()
    {
        // ARRANGE: Mock 429 Too Many Requests (rate limit)
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Rate limit exceeded'], 429),
        ]);

        Queue::fake();

        $payload = ['event' => 'user.login', 'data' => ['user_id' => 789]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(429, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);

        // ASSERT: Error message captured
        $this->assertStringContainsString('Rate limit', $delivery->error_message ?? '');

        // ASSERT: Retry job scheduled
        Queue::assertPushed(RetryWebhookDeliveryJob::class);
    }

    // ============================================================
    // HTTP STATUS-BASED RETRY LOGIC: 5XX
    // ============================================================

    #[Test]
    public function retry_triggered_on_500_server_error()
    {
        // ARRANGE: Mock 500 Internal Server Error
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Server error'], 500),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 500]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(500, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
        $this->assertNotNull($delivery->next_retry_at);

        // ASSERT: Retry job scheduled
        Queue::assertPushed(RetryWebhookDeliveryJob::class);
    }

    #[Test]
    public function retry_triggered_on_502_bad_gateway()
    {
        // ARRANGE: Mock 502 Bad Gateway
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Bad Gateway'], 502),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 502]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(502, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
        $this->assertNotNull($delivery->next_retry_at);

        // ASSERT: Retry job scheduled
        Queue::assertPushed(RetryWebhookDeliveryJob::class);
    }

    #[Test]
    public function retry_triggered_on_503_service_unavailable()
    {
        // ARRANGE: Mock 503 Service Unavailable
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Service Unavailable'], 503),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 503]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(503, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
        $this->assertNotNull($delivery->next_retry_at);

        // ASSERT: Retry job scheduled
        Queue::assertPushed(RetryWebhookDeliveryJob::class);
    }

    #[Test]
    public function retry_triggered_on_504_gateway_timeout()
    {
        // ARRANGE: Mock 504 Gateway Timeout
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Gateway Timeout'], 504),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 504]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed but marked for retry
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(504, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
        $this->assertNotNull($delivery->next_retry_at);

        // ASSERT: Retry job scheduled
        Queue::assertPushed(RetryWebhookDeliveryJob::class);
    }

    // ============================================================
    // NO RETRY ON SUCCESS (2XX)
    // ============================================================

    #[Test]
    public function no_retry_on_successful_2xx_responses()
    {
        // ARRANGE: Mock successful responses
        Http::fake([
            'example.com/*' => Http::response(['status' => 'ok'], 200),
        ]);

        Queue::fake();

        $payload = ['event' => 'user.created', 'data' => ['user_id' => 999]];

        // ACT: Deliver webhook successfully
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery successful
        $this->assertTrue($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(200, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::SUCCESS, $delivery->status);

        // ASSERT: No retry scheduled
        $this->assertNull($delivery->next_retry_at);
        $this->assertEquals(1, $delivery->attempt_number);

        // ASSERT: No retry job dispatched
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    // ============================================================
    // NO RETRY ON CLIENT ERRORS (4XX EXCEPT 408/429)
    // ============================================================

    #[Test]
    public function no_retry_on_400_bad_request()
    {
        // ARRANGE: Mock 400 Bad Request
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Bad Request'], 400),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 400]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed and marked as permanently failed
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(400, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::FAILED, $delivery->status);

        // ASSERT: No retry scheduled (completed_at set)
        $this->assertNotNull($delivery->completed_at);
        $this->assertEquals(1, $delivery->attempt_number);

        // ASSERT: No retry job dispatched
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    #[Test]
    public function no_retry_on_401_unauthorized()
    {
        // ARRANGE: Mock 401 Unauthorized
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Unauthorized'], 401),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 401]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed and marked as permanently failed
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(401, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::FAILED, $delivery->status);

        // ASSERT: No retry scheduled
        $this->assertNotNull($delivery->completed_at);
        $this->assertEquals(1, $delivery->attempt_number);

        // ASSERT: No retry job dispatched
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    #[Test]
    public function no_retry_on_403_forbidden()
    {
        // ARRANGE: Mock 403 Forbidden
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Forbidden'], 403),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 403]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed and marked as permanently failed
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(403, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::FAILED, $delivery->status);

        // ASSERT: No retry scheduled
        $this->assertNotNull($delivery->completed_at);
        $this->assertEquals(1, $delivery->attempt_number);

        // ASSERT: No retry job dispatched
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    #[Test]
    public function no_retry_on_404_not_found()
    {
        // ARRANGE: Mock 404 Not Found
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Not Found'], 404),
        ]);

        Queue::fake();

        $payload = ['event' => 'test.event', 'data' => ['test' => 404]];

        // ACT: Attempt delivery
        $result = $this->deliveryService->deliverWebhook($this->webhook, $payload);

        // ASSERT: Delivery failed and marked as permanently failed
        $this->assertFalse($result->success);

        $delivery = WebhookDelivery::find($result->delivery_id);
        $this->assertEquals(404, $delivery->http_status_code);
        $this->assertEquals(WebhookDeliveryStatus::FAILED, $delivery->status);

        // ASSERT: No retry scheduled
        $this->assertNotNull($delivery->completed_at);
        $this->assertEquals(1, $delivery->attempt_number);

        // ASSERT: No retry job dispatched
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    // ============================================================
    // MAX 6 ATTEMPTS ENFORCEMENT
    // ============================================================

    #[Test]
    public function max_6_attempts_enforcement_stops_retries()
    {
        // ARRANGE: Create delivery at max attempts (6)
        $delivery = WebhookDelivery::factory()->create([
            'webhook_id' => $this->webhook->id,
            'attempt_number' => 6, // Max attempts reached
            'max_attempts' => 6,
            'status' => WebhookDeliveryStatus::RETRYING,
        ]);

        // Mock server error (normally retryable)
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Server error'], 500),
        ]);

        Queue::fake();

        // ACT: Attempt delivery at max attempts
        $success = $this->deliveryService->deliver($delivery);

        // ASSERT: Delivery failed permanently (no more retries)
        $this->assertFalse($success);

        $delivery->refresh();
        $this->assertEquals(WebhookDeliveryStatus::FAILED, $delivery->status);
        $this->assertTrue($delivery->hasReachedMaxAttempts());

        // ASSERT: No retry job scheduled (max attempts reached)
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    // ============================================================
    // RETRY JOB SCHEDULING
    // ============================================================

    #[Test]
    public function retry_job_scheduling_uses_correct_delays()
    {
        Queue::fake();

        // Test delays for attempts 1-5 (attempt 6 is final, no retry)
        $attemptsWithDelays = [
            1 => 1,      // 1 minute
            2 => 5,      // 5 minutes
            3 => 15,     // 15 minutes
            4 => 60,     // 1 hour
            5 => 360,    // 6 hours
        ];

        foreach ($attemptsWithDelays as $attemptNumber => $expectedDelayMinutes) {
            // ARRANGE: Create delivery at specific attempt
            $delivery = WebhookDelivery::factory()->create([
                'webhook_id' => $this->webhook->id,
                'attempt_number' => $attemptNumber,
                'max_attempts' => 6,
                'status' => WebhookDeliveryStatus::FAILED,
            ]);

            // ACT: Schedule retry
            $this->deliveryService->scheduleRetry($delivery);

            // ASSERT: Retry job dispatched with correct delay
            Queue::assertPushed(RetryWebhookDeliveryJob::class, function ($job) use ($delivery, $expectedDelayMinutes) {
                // Job delay is a Carbon instance, check diffInMinutes from now
                $delayMinutes = abs(now()->diffInMinutes($job->delay));
                $tolerance = max(2, $expectedDelayMinutes * 0.1); // 10% tolerance or 2 min minimum

                return $job->delivery->id === $delivery->id &&
                       $delayMinutes >= ($expectedDelayMinutes - $tolerance) &&
                       $delayMinutes <= ($expectedDelayMinutes + $tolerance);
            });
        }
    }

    // ============================================================
    // SUCCESS AFTER RETRY
    // ============================================================

    #[Test]
    public function successful_delivery_after_previous_failures()
    {
        // ARRANGE: Create delivery with previous failure
        $delivery = WebhookDelivery::factory()->create([
            'webhook_id' => $this->webhook->id,
            'attempt_number' => 2, // Second attempt
            'max_attempts' => 6,
            'status' => WebhookDeliveryStatus::RETRYING,
        ]);

        // Mock successful response on retry
        Http::fake([
            'example.com/*' => Http::response(['status' => 'ok'], 200),
        ]);

        Queue::fake();

        // ACT: Retry delivery
        $success = $this->deliveryService->deliver($delivery);

        // ASSERT: Delivery succeeded on retry
        $this->assertTrue($success);

        $delivery->refresh();
        $this->assertEquals(WebhookDeliveryStatus::SUCCESS, $delivery->status);
        $this->assertEquals(200, $delivery->http_status_code);

        // ASSERT: No further retry scheduled
        $this->assertNull($delivery->next_retry_at);

        // ASSERT: Webhook failure counters reset
        $this->webhook->refresh();
        $this->assertEquals(0, $this->webhook->consecutive_failures);

        // ASSERT: No retry job dispatched (success)
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);
    }

    // ============================================================
    // RETRY COUNTER INCREMENTS
    // ============================================================

    #[Test]
    public function retry_counter_increments_with_each_attempt()
    {
        Queue::fake();

        // ARRANGE: Create delivery at attempt 1
        $delivery = WebhookDelivery::factory()->create([
            'webhook_id' => $this->webhook->id,
            'attempt_number' => 1,
            'max_attempts' => 6,
            'status' => WebhookDeliveryStatus::FAILED,
        ]);

        // ACT: Schedule retry multiple times
        for ($i = 1; $i <= 5; $i++) {
            $previousAttempt = $delivery->attempt_number;

            $this->deliveryService->scheduleRetry($delivery);

            $delivery->refresh();

            // ASSERT: Attempt number incremented
            $this->assertEquals($previousAttempt + 1, $delivery->attempt_number);
            $this->assertEquals(WebhookDeliveryStatus::RETRYING, $delivery->status);
            $this->assertNotNull($delivery->next_retry_at);
        }

        // ASSERT: Final attempt number is 6
        $this->assertEquals(6, $delivery->attempt_number);

        // ASSERT: 5 retry jobs dispatched (attempts 1-5)
        Queue::assertPushed(RetryWebhookDeliveryJob::class, 5);
    }

    // ============================================================
    // FINAL FAILURE AFTER MAX RETRIES
    // ============================================================

    #[Test]
    public function permanent_failure_after_max_retries_exhausted()
    {
        // ARRANGE: Create delivery at final attempt
        $delivery = WebhookDelivery::factory()->create([
            'webhook_id' => $this->webhook->id,
            'attempt_number' => 6, // Final attempt
            'max_attempts' => 6,
            'status' => WebhookDeliveryStatus::RETRYING,
        ]);

        // Mock server error (normally retryable)
        Http::fake([
            'example.com/*' => Http::response(['error' => 'Server error'], 500),
        ]);

        Queue::fake();

        // ACT: Attempt final delivery
        $success = $this->deliveryService->deliver($delivery);

        // ASSERT: Delivery failed permanently
        $this->assertFalse($success);

        $delivery->refresh();
        $this->assertEquals(WebhookDeliveryStatus::FAILED, $delivery->status);
        $this->assertEquals(500, $delivery->http_status_code);
        $this->assertNotNull($delivery->completed_at);

        // ASSERT: Max attempts reached
        $this->assertTrue($delivery->hasReachedMaxAttempts());
        $this->assertFalse($delivery->canRetry());

        // ASSERT: No retry job dispatched (max attempts reached)
        Queue::assertNotPushed(RetryWebhookDeliveryJob::class);

        // ASSERT: Webhook failure counter incremented
        $this->webhook->refresh();
        $this->assertGreaterThan(0, $this->webhook->consecutive_failures);
    }
}
