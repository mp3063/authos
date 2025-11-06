<?php

namespace Tests\Integration\Monitoring;

use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\Integration\IntegrationTestCase;

/**
 * Health Check Integration Tests
 *
 * Tests the health check endpoints used for monitoring system status,
 * Kubernetes probes, and service availability checks.
 *
 * Endpoints tested:
 * - GET /api/v1/health (basic liveness)
 * - GET /api/v1/health/detailed (comprehensive health)
 * - GET /api/v1/health/readiness (K8s readiness probe)
 * - GET /api/v1/health/liveness (K8s liveness probe)
 * - GET /api/v1/health/{component} (component-specific health)
 */
class HealthCheckTest extends IntegrationTestCase
{
    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = $this->createUser();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function basic_health_check_returns_ok_status(): void
    {
        // ARRANGE: System is running normally

        // ACT: Request basic health check
        $response = $this->getJson('/api/health');

        // ASSERT: Response indicates system is healthy
        $response->assertOk();
        $response->assertJsonStructure([
            'status',
            'timestamp',
        ]);

        $data = $response->json();
        $this->assertEquals('ok', $data['status']);
        $this->assertNotEmpty($data['timestamp']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function detailed_health_check_includes_all_components(): void
    {
        // ARRANGE: Authenticated user with monitoring access (using Passport token)
        $this->actingAsApiUserWithToken($this->user);

        // ACT: Request detailed health check
        $response = $this->getJson('/api/v1/monitoring/health');

        // ASSERT: Response includes all service checks
        $response->assertOk();
        $response->assertJsonStructure([
            'status',
            'timestamp',
            'services' => [
                'database',
                'cache',
                'redis',
            ],
            'checks' => [
                'database',
                'cache',
            ],
            'version',
            'environment',
        ]);

        $data = $response->json();
        $this->assertContains($data['status'], ['ok', 'healthy', 'degraded']);
        $this->assertNotEmpty($data['version']);
        $this->assertNotEmpty($data['environment']);

        // Verify service statuses
        foreach ($data['services'] as $service => $status) {
            $this->assertContains(
                $status,
                ['ok', 'healthy', 'degraded', 'unhealthy', 'not_configured'],
                "Service {$service} has invalid status: {$status}"
            );
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function readiness_check_verifies_critical_services(): void
    {
        // ARRANGE: Authenticated user
        $this->actingAs($this->user);

        // ACT: Request readiness check (K8s probe)
        $response = $this->getJson('/api/health/readiness');

        // ASSERT: Readiness probe returns ready status
        $response->assertOk();
        $response->assertJsonStructure([
            'ready',
            'timestamp',
            'checks',
        ]);

        $data = $response->json();
        $this->assertTrue($data['ready'], 'System should be ready');
        $this->assertIsArray($data['checks']);
        $this->assertNotEmpty($data['timestamp']);

        // Verify critical services are checked
        $this->assertArrayHasKey('database', $data['checks']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function liveness_check_confirms_application_running(): void
    {
        // ARRANGE: Authenticated user
        $this->actingAs($this->user);

        // ACT: Request liveness check (K8s probe)
        $response = $this->getJson('/api/health/liveness');

        // ASSERT: Liveness probe confirms app is alive
        $response->assertOk();
        $response->assertJsonStructure([
            'alive',
            'timestamp',
        ]);

        $data = $response->json();
        $this->assertTrue($data['alive']);
        $this->assertNotEmpty($data['timestamp']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function database_component_health_check_succeeds(): void
    {
        // ARRANGE: Authenticated user, database is operational
        $this->actingAs($this->user);

        // Verify database is accessible
        $this->assertTrue(DB::connection()->getDatabaseName() !== null);

        // ACT: Check database component health
        $response = $this->getJson('/api/health/database');

        // ASSERT: Database health check passes
        $response->assertOk();
        $response->assertJsonStructure([
            'component',
            'result' => [
                'status',
            ],
            'timestamp',
        ]);

        $data = $response->json();
        $this->assertEquals('database', $data['component']);
        $this->assertContains(
            $data['result']['status'],
            ['healthy', 'ok']
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cache_component_health_check_succeeds(): void
    {
        // ARRANGE: Authenticated user, cache is operational
        $this->actingAs($this->user);

        // Verify cache is working
        Cache::put('health_check_test', 'ok', 10);
        $this->assertEquals('ok', Cache::get('health_check_test'));

        // ACT: Check cache component health
        $response = $this->getJson('/api/health/cache');

        // ASSERT: Cache health check passes
        $response->assertOk();
        $response->assertJsonStructure([
            'component',
            'result' => [
                'status',
            ],
            'timestamp',
        ]);

        $data = $response->json();
        $this->assertEquals('cache', $data['component']);
        $this->assertContains(
            $data['result']['status'],
            ['healthy', 'ok']
        );

        // Cleanup
        Cache::forget('health_check_test');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function invalid_component_returns_error(): void
    {
        // ARRANGE: Authenticated user
        $this->actingAs($this->user);

        // ACT: Request health check for invalid component
        $response = $this->getJson('/api/health/invalid_component');

        // ASSERT: Returns 404 with valid components list
        $response->assertNotFound();
        $response->assertJsonStructure([
            'error',
            'valid_components',
        ]);

        $data = $response->json();
        $this->assertIsArray($data['valid_components']);
        $this->assertNotEmpty($data['valid_components']);
    }
}
