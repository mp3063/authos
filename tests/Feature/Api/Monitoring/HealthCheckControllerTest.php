<?php

namespace Tests\Feature\Api\Monitoring;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class HealthCheckControllerTest extends TestCase
{
    use RefreshDatabase;

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_basic_health_check(): void
    {
        $response = $this->getJson('/api/health');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'timestamp',
            ])
            ->assertJson([
                'status' => 'ok',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_detailed_health_check(): void
    {
        $response = $this->getJson('/api/health/detailed');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'status',
                'timestamp',
                'checks' => [
                    'database',
                    'cache',
                    'oauth',
                    'storage',
                    'queue',
                ],
                'version',
                'environment',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_readiness_probe(): void
    {
        $response = $this->getJson('/api/health/readiness');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'ready',
                'timestamp',
                'checks',
            ])
            ->assertJson([
                'ready' => true,
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_liveness_probe(): void
    {
        $response = $this->getJson('/api/health/liveness');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'alive',
                'timestamp',
            ])
            ->assertJson([
                'alive' => true,
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_component_health(): void
    {
        $response = $this->getJson('/api/health/database');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'component',
                'result' => [
                    'status',
                    'message',
                ],
                'timestamp',
            ])
            ->assertJson([
                'component' => 'database',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_404_for_invalid_component(): void
    {
        $response = $this->getJson('/api/health/invalid');

        $response->assertStatus(404)
            ->assertJsonStructure([
                'error',
                'valid_components',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_all_valid_components(): void
    {
        $components = ['database', 'cache', 'oauth', 'storage', 'queue'];

        foreach ($components as $component) {
            $response = $this->getJson("/api/health/{$component}");

            $response->assertStatus(200)
                ->assertJson([
                    'component' => $component,
                ]);
        }
    }
}
