<?php

namespace Tests\Unit\Services\Monitoring;

use App\Services\Monitoring\HealthCheckService;
use Tests\TestCase;

class HealthCheckServiceTest extends TestCase
{
    private HealthCheckService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new HealthCheckService;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_overall_health(): void
    {
        $result = $this->service->checkHealth();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertArrayHasKey('checks', $result);
        $this->assertArrayHasKey('version', $result);
        $this->assertArrayHasKey('environment', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_database_health(): void
    {
        $result = $this->service->checkDatabase();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertEquals('healthy', $result['status']);
        $this->assertArrayHasKey('response_time_ms', $result);
        $this->assertArrayHasKey('driver', $result);
        $this->assertArrayHasKey('database', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_cache_health(): void
    {
        $result = $this->service->checkCache();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertEquals('healthy', $result['status']);
        $this->assertArrayHasKey('response_time_ms', $result);
        $this->assertArrayHasKey('driver', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_oauth_health(): void
    {
        $result = $this->service->checkOAuth();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('response_time_ms', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_storage_health(): void
    {
        $result = $this->service->checkStorage();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertEquals('healthy', $result['status']);
        $this->assertArrayHasKey('writable', $result);
        $this->assertTrue($result['writable']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_queue_health(): void
    {
        $result = $this->service->checkQueue();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('driver', $result);
        $this->assertArrayHasKey('failed_jobs', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_performs_detailed_health_check(): void
    {
        $result = $this->service->checkHealth(detailed: true);

        $this->assertArrayHasKey('checks', $result);
        $this->assertArrayHasKey('ldap', $result['checks']);
        $this->assertArrayHasKey('email', $result['checks']);
        $this->assertArrayHasKey('disk_space', $result['checks']);
        $this->assertArrayHasKey('php_extensions', $result['checks']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_readiness(): void
    {
        $result = $this->service->checkReadiness();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('ready', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertArrayHasKey('checks', $result);
        $this->assertTrue($result['ready']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_liveness(): void
    {
        $result = $this->service->checkLiveness();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('alive', $result);
        $this->assertArrayHasKey('timestamp', $result);
        $this->assertTrue($result['alive']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_unhealthy_database(): void
    {
        // Create a partial mock of the service to simulate database failure
        $service = \Mockery::mock(HealthCheckService::class)->makePartial();
        $service->shouldReceive('checkDatabase')
            ->once()
            ->andReturn([
                'status' => 'unhealthy',
                'error' => 'Connection refused',
            ]);

        $result = $service->checkDatabase();

        $this->assertEquals('unhealthy', $result['status']);
        $this->assertArrayHasKey('error', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_php_extensions(): void
    {
        $result = $this->service->checkPhpExtensions();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('required', $result);
        $this->assertArrayHasKey('missing', $result);
        $this->assertEquals('healthy', $result['status']);
        $this->assertEmpty($result['missing']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_disk_space(): void
    {
        $result = $this->service->checkDiskSpace();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('free_space_bytes', $result);
        $this->assertArrayHasKey('total_space_bytes', $result);
        $this->assertArrayHasKey('used_percentage', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_overall_status_correctly(): void
    {
        $result = $this->service->checkHealth();

        $this->assertContains($result['status'], ['healthy', 'degraded', 'unhealthy', 'critical']);
    }
}
