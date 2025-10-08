<?php

namespace Tests\Feature\Api\Monitoring;

use App\Models\User;
use Laravel\Passport\Passport;
use Tests\TestCase;

class MetricsControllerTest extends TestCase
{
    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = User::factory()->create();
        Passport::actingAs($this->user);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_requires_authentication_for_metrics(): void
    {
        // Create a new test instance without authentication
        // We need to bypass the setUp() which calls Passport::actingAs()
        $this->app['auth']->forgetGuards();

        $response = $this->withHeaders([
            'Accept' => 'application/json',
        ])->getJson('/api/v1/monitoring/metrics');

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_all_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'authentication',
                'oauth',
                'api',
                'webhooks',
                'users',
                'organizations',
                'mfa',
                'performance',
                'timestamp',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_authentication_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/authentication');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'today' => [
                    'total_attempts',
                    'successful',
                    'failed',
                    'success_rate',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_oauth_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/oauth');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'active_tokens',
                'tokens_created_today',
                'active_refresh_tokens',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_api_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/api');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'total_requests',
                'total_errors',
                'error_rate',
                'avg_response_time_ms',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_webhook_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/webhooks');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'total_webhooks',
                'active_webhooks',
                'deliveries_today',
                'success_rate',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_user_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/users');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'total_users',
                'new_users',
                'active_users',
                'mfa',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_organization_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/organizations');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'total_organizations',
                'new_organizations',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_mfa_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/mfa');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'enabled_users',
                'usage',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_performance_metrics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/performance');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'avg_response_time_ms',
                'cache',
                'slow_queries_count',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_error_statistics(): void
    {
        $response = $this->getJson('/api/v1/monitoring/errors');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'critical',
                'error',
                'warning',
                'total',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_error_trends(): void
    {
        $response = $this->getJson('/api/v1/monitoring/errors/trends?days=7');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'trends',
                'days',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_recent_errors(): void
    {
        $response = $this->getJson('/api/v1/monitoring/errors/recent?limit=10');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'errors',
                'count',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_records_custom_metrics(): void
    {
        $response = $this->postJson('/api/v1/monitoring/metrics/record', [
            'name' => 'test_metric',
            'value' => 100,
            'tags' => ['env' => 'test'],
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Metric recorded successfully',
                'metric' => 'test_metric',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_custom_metric_input(): void
    {
        $response = $this->postJson('/api/v1/monitoring/metrics/record', [
            'name' => '',
            'value' => 'invalid',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'value']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_custom_metric(): void
    {
        // Record a metric first
        $this->postJson('/api/v1/monitoring/metrics/record', [
            'name' => 'test_metric',
            'value' => 100,
        ]);

        $response = $this->getJson('/api/v1/monitoring/metrics/test_metric');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'name',
                'count',
                'sum',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_404_for_nonexistent_metric(): void
    {
        $response = $this->getJson('/api/v1/monitoring/metrics/nonexistent');

        $response->assertStatus(404)
            ->assertJson([
                'error' => 'Metric not found',
            ]);
    }
}
