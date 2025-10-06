<?php

declare(strict_types=1);

namespace Tests\Feature\Services\Auth0;

use App\Models\Organization;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Migration\Auth0MigrationService;
use App\Services\Auth0\Migration\MigrationPlan;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Mockery;
use Tests\TestCase;

class MigrationServiceTest extends TestCase
{
    use RefreshDatabase;

    private Auth0Client $mockClient;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->mockClient = Mockery::mock(Auth0Client::class);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_empty_migration_plan(): void
    {
        $plan = new MigrationPlan;

        $this->assertEquals(0, $plan->getTotalItems());
        $this->assertTrue($plan->isEmpty());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_exports_migration_plan_to_json(): void
    {
        $plan = new MigrationPlan;

        $json = $plan->exportToJson();
        $data = json_decode($json, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('organizations', $data);
        $this->assertArrayHasKey('roles', $data);
        $this->assertArrayHasKey('applications', $data);
        $this->assertArrayHasKey('users', $data);
        $this->assertArrayHasKey('summary', $data);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_performs_dry_run_migration(): void
    {
        $service = new Auth0MigrationService($this->mockClient, $this->organization);
        $plan = new MigrationPlan;

        $result = $service->migrate($plan, true);

        $this->assertTrue($result->dryRun);
        $this->assertEquals(0, $result->getSuccessCount());
        $this->assertEquals(0, $result->getFailureCount());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_migration_duration(): void
    {
        $service = new Auth0MigrationService($this->mockClient, $this->organization);
        $plan = new MigrationPlan;

        $result = $service->migrate($plan, true);
        $result->markCompleted();

        $duration = $result->getDuration();

        $this->assertNotNull($duration);
        $this->assertGreaterThanOrEqual(0, $duration);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_generates_migration_report(): void
    {
        $service = new Auth0MigrationService($this->mockClient, $this->organization);
        $plan = new MigrationPlan;

        $result = $service->migrate($plan, true);
        $result->markCompleted();

        $report = $result->getReport();

        $this->assertArrayHasKey('started_at', $report);
        $this->assertArrayHasKey('completed_at', $report);
        $this->assertArrayHasKey('duration_seconds', $report);
        $this->assertArrayHasKey('dry_run', $report);
        $this->assertArrayHasKey('total', $report);
        $this->assertArrayHasKey('successful', $report);
        $this->assertArrayHasKey('failed', $report);
        $this->assertArrayHasKey('skipped', $report);
        $this->assertArrayHasKey('success_rate', $report);
        $this->assertArrayHasKey('organizations', $report);
        $this->assertArrayHasKey('roles', $report);
        $this->assertArrayHasKey('applications', $report);
        $this->assertArrayHasKey('users', $report);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_exports_migration_result_to_json(): void
    {
        $service = new Auth0MigrationService($this->mockClient, $this->organization);
        $plan = new MigrationPlan;

        $result = $service->migrate($plan, true);
        $result->markCompleted();

        $json = $result->exportToJson();
        $data = json_decode($json, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('started_at', $data);
        $this->assertArrayHasKey('completed_at', $data);
    }
}
