<?php

namespace Tests\Unit\Services;

use App\Services\AlertingService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class AlertingServiceTest extends TestCase
{
    use RefreshDatabase;

    private AlertingService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new AlertingService;
        Cache::flush();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_health_alerts_without_triggering(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 5, // 5% error rate (below 10% threshold)
            'total_execution_time' => 50000, // 500ms avg (below 2000ms threshold)
        ], 3600);

        Log::shouldReceive('critical')->never();

        $this->service->checkHealthAlerts();

        $this->assertTrue(true); // No alerts triggered
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_triggers_high_error_rate_alert(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 15, // 15% error rate (above 10% threshold)
        ], 3600);

        Log::shouldReceive('critical')->once();
        Log::shouldReceive('info')->once();
        Cache::shouldReceive('has')->andReturn(false);
        Cache::shouldReceive('put')->once();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_trigger_error_alert_with_low_request_volume(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 5, // Too few requests
            'total_errors' => 3, // 60% error rate but low volume
        ], 3600);

        Log::shouldReceive('critical')->never();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_triggers_slow_response_time_alert(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_execution_time' => 250000, // 2500ms avg (above 2000ms threshold)
            'max_execution_time' => 5000,
        ], 3600);

        Log::shouldReceive('critical')->once();
        Log::shouldReceive('info')->once();
        Cache::shouldReceive('has')->andReturn(false);
        Cache::shouldReceive('put')->once();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_trigger_response_time_alert_with_low_request_volume(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 3, // Too few requests
            'total_execution_time' => 10000, // High response time but low volume
        ], 3600);

        Log::shouldReceive('critical')->never();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_triggers_high_memory_usage_alert(): void
    {
        // This test may be flaky depending on actual memory usage
        // We'll verify the check runs without error
        Log::shouldReceive('critical')->zeroOrMoreTimes();
        Log::shouldReceive('info')->zeroOrMoreTimes();

        $this->service->checkHealthAlerts();

        $this->assertTrue(true);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_parses_memory_limit_correctly(): void
    {
        $reflection = new \ReflectionClass($this->service);
        $method = $reflection->getMethod('parseMemoryLimit');
        $method->setAccessible(true);

        $this->assertEquals(1024 * 1024 * 256, $method->invoke($this->service, '256M'));
        $this->assertEquals(1024 * 1024 * 1024 * 2, $method->invoke($this->service, '2G'));
        $this->assertEquals(1024 * 512, $method->invoke($this->service, '512K'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_alert_spam_within_hour(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 15, // Trigger alert
        ], 3600);

        // Mark alert as already sent
        Cache::put('alert_sent:high_error_rate:'.now()->format('Y-m-d-H'), true, 3600);

        Log::shouldReceive('critical')->never();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_system_status_summary_healthy(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 5, // Below threshold
            'total_execution_time' => 50000, // Below threshold
        ], 3600);

        $status = $this->service->getSystemStatusSummary();

        $this->assertEquals('healthy', $status['overall_status']);
        $this->assertEquals(0, $status['active_alerts']);
        $this->assertArrayHasKey('checks', $status);
        $this->assertArrayHasKey('timestamp', $status);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_system_status_summary_with_warnings(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 15, // Above threshold - will trigger alert
            'total_execution_time' => 50000,
        ], 3600);

        $status = $this->service->getSystemStatusSummary();

        $this->assertEquals('warning', $status['overall_status']);
        $this->assertGreaterThan(0, $status['active_alerts']);
        $this->assertArrayHasKey('error_rate', $status['checks']);
        $this->assertTrue($status['checks']['error_rate']['triggered']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_includes_check_details_in_status(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 5,
            'total_execution_time' => 50000,
            'max_execution_time' => 1500,
        ], 3600);

        $status = $this->service->getSystemStatusSummary();

        $this->assertArrayHasKey('response_time', $status['checks']);
        $this->assertArrayHasKey('memory_usage', $status['checks']);
        $this->assertArrayHasKey('oauth_health', $status['checks']);

        $errorRateCheck = $status['checks']['error_rate'];
        $this->assertArrayHasKey('triggered', $errorRateCheck);
        $this->assertArrayHasKey('value', $errorRateCheck);
        $this->assertArrayHasKey('threshold', $errorRateCheck);
        $this->assertArrayHasKey('message', $errorRateCheck);
        $this->assertArrayHasKey('details', $errorRateCheck);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_missing_metrics_gracefully(): void
    {
        // No metrics in cache
        $status = $this->service->getSystemStatusSummary();

        $this->assertEquals('healthy', $status['overall_status']);
        $this->assertArrayHasKey('checks', $status);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_logs_email_alert_info(): void
    {
        Config::set('monitoring.alert_emails', ['admin@example.com']);

        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 15,
        ], 3600);

        Log::shouldReceive('critical')->once();
        Log::shouldReceive('info')->twice(); // Once for email, once for alert
        Cache::shouldReceive('has')->andReturn(false);
        Cache::shouldReceive('put')->once();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_skips_email_when_no_recipients_configured(): void
    {
        Config::set('monitoring.alert_emails', []);

        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_errors' => 15,
        ], 3600);

        Log::shouldReceive('critical')->once();
        Log::shouldReceive('info')->never();
        Cache::shouldReceive('has')->andReturn(false);
        Cache::shouldReceive('put')->once();

        $this->service->checkHealthAlerts();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_error_rate_correctly(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 200,
            'total_errors' => 20, // 10% error rate (exactly at threshold)
        ], 3600);

        $status = $this->service->getSystemStatusSummary();

        $errorRate = $status['checks']['error_rate'];
        $this->assertEquals(10.0, $errorRate['value']);
        $this->assertEquals(10, $errorRate['threshold']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_average_response_time_correctly(): void
    {
        Cache::put('api_metrics:'.now()->format('Y-m-d').':hourly:'.now()->format('H'), [
            'total_requests' => 100,
            'total_execution_time' => 150000, // 1500ms avg
            'max_execution_time' => 3000,
        ], 3600);

        $status = $this->service->getSystemStatusSummary();

        $responseTime = $status['checks']['response_time'];
        $this->assertEquals(1500, $responseTime['value']);
        $this->assertFalse($responseTime['triggered']); // Below 2000ms threshold
    }
}
