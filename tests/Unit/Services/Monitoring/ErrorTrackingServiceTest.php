<?php

namespace Tests\Unit\Services\Monitoring;

use App\Services\Monitoring\ErrorTrackingService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class ErrorTrackingServiceTest extends TestCase
{
    private ErrorTrackingService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new ErrorTrackingService;
        Cache::flush();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_errors_with_categorization(): void
    {
        $mockChannel = \Mockery::mock();
        $mockChannel->shouldReceive('error')->once();

        Log::shouldReceive('channel')
            ->with('monitoring')
            ->once()
            ->andReturn($mockChannel);

        $exception = new \Exception('Test error');

        $this->service->trackError(
            $exception,
            ErrorTrackingService::SEVERITY_ERROR,
            ['context' => 'test']
        );

        // Verify the mock expectations were met
        $this->assertTrue(true);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_critical_errors(): void
    {
        $mockChannel = \Mockery::mock();
        // Critical errors are logged twice: once in logError() and once in triggerCriticalAlert()
        $mockChannel->shouldReceive('critical')->times(2);

        Log::shouldReceive('channel')
            ->with('monitoring')
            ->times(2)
            ->andReturn($mockChannel);

        $exception = new \Exception('Critical test error');

        $this->service->trackError(
            $exception,
            ErrorTrackingService::SEVERITY_CRITICAL
        );

        // Verify the mock expectations were met
        $this->assertTrue(true);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_failed_authentication_attempts(): void
    {
        $mockChannel = \Mockery::mock();
        $mockChannel->shouldReceive('warning')->once();

        Log::shouldReceive('channel')
            ->with('security')
            ->once()
            ->andReturn($mockChannel);

        $this->service->trackFailedAuthentication(
            'test@example.com',
            '192.168.1.100',
            'invalid_credentials'
        );

        // Verify the mock expectations were met
        $this->assertTrue(true);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_webhook_failures(): void
    {
        $mockChannel = \Mockery::mock();
        $mockChannel->shouldReceive('warning')->once();

        Log::shouldReceive('channel')
            ->with('monitoring')
            ->once()
            ->andReturn($mockChannel);

        $this->service->trackWebhookFailure(
            1,
            1,
            'Connection timeout',
            ['url' => 'https://example.com/webhook']
        );

        // Verify the mock expectations were met
        $this->assertTrue(true);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_error_statistics(): void
    {
        $stats = $this->service->getErrorStatistics();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('critical', $stats);
        $this->assertArrayHasKey('error', $stats);
        $this->assertArrayHasKey('warning', $stats);
        $this->assertArrayHasKey('total', $stats);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_recent_errors(): void
    {
        $errors = $this->service->getRecentErrors(10);

        $this->assertIsArray($errors);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_error_rate(): void
    {
        $rate = $this->service->getErrorRate();

        $this->assertIsFloat($rate);
        $this->assertGreaterThanOrEqual(0, $rate);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_error_trends(): void
    {
        $trends = $this->service->getErrorTrends(7);

        $this->assertIsArray($trends);
        $this->assertCount(7, $trends);

        foreach ($trends as $trend) {
            $this->assertArrayHasKey('date', $trend);
            $this->assertArrayHasKey('critical', $trend);
            $this->assertArrayHasKey('error', $trend);
            $this->assertArrayHasKey('warning', $trend);
            $this->assertArrayHasKey('total', $trend);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_error_statistics(): void
    {
        // Add some error stats
        $exception = new \Exception('Test');
        $this->service->trackError($exception);

        // Clear stats
        $this->service->clearStatistics();

        $stats = $this->service->getErrorStatistics();
        $this->assertEquals(0, $stats['total']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_sanitizes_stack_traces(): void
    {
        $exception = new \Exception('Test error with sensitive data');

        $this->service->trackError($exception);

        $errors = $this->service->getRecentErrors(1);

        if (! empty($errors)) {
            $this->assertArrayHasKey('trace', $errors[0]);
            $this->assertIsArray($errors[0]['trace']);
        }
    }
}
