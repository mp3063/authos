<?php

namespace Tests\Unit\Services\Monitoring;

use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Services\Monitoring\MetricsCollectionService;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class MetricsCollectionServiceTest extends TestCase
{
    private MetricsCollectionService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->artisan('migrate');
        $this->service = new MetricsCollectionService;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_collects_all_metrics(): void
    {
        $metrics = $this->service->collectAllMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('authentication', $metrics);
        $this->assertArrayHasKey('oauth', $metrics);
        $this->assertArrayHasKey('api', $metrics);
        $this->assertArrayHasKey('webhooks', $metrics);
        $this->assertArrayHasKey('users', $metrics);
        $this->assertArrayHasKey('organizations', $metrics);
        $this->assertArrayHasKey('mfa', $metrics);
        $this->assertArrayHasKey('performance', $metrics);
        $this->assertArrayHasKey('timestamp', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_authentication_metrics(): void
    {
        // Create test data
        $user = User::factory()->create();
        AuthenticationLog::factory()->create([
            'user_id' => $user->id,
            'success' => true,
            'created_at' => now(),
        ]);

        AuthenticationLog::factory()->create([
            'user_id' => $user->id,
            'success' => false,
            'created_at' => now(),
        ]);

        Cache::forget('metrics:authentication');

        $metrics = $this->service->getAuthenticationMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('today', $metrics);
        $this->assertArrayHasKey('total_attempts', $metrics['today']);
        $this->assertArrayHasKey('successful', $metrics['today']);
        $this->assertArrayHasKey('failed', $metrics['today']);
        $this->assertArrayHasKey('success_rate', $metrics['today']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_oauth_metrics(): void
    {
        Cache::forget('metrics:oauth');

        $metrics = $this->service->getOAuthMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('active_tokens', $metrics);
        $this->assertArrayHasKey('tokens_created_today', $metrics);
        $this->assertArrayHasKey('active_refresh_tokens', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_api_metrics(): void
    {
        $metrics = $this->service->getApiMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('total_requests', $metrics);
        $this->assertArrayHasKey('total_errors', $metrics);
        $this->assertArrayHasKey('error_rate', $metrics);
        $this->assertArrayHasKey('avg_response_time_ms', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_webhook_metrics(): void
    {
        // Create test data
        $webhook = Webhook::factory()->create(['is_active' => true]);
        WebhookDelivery::factory()->create([
            'webhook_id' => $webhook->id,
            'status' => 'success',
            'created_at' => now(),
        ]);

        Cache::forget('metrics:webhooks');

        $metrics = $this->service->getWebhookMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('total_webhooks', $metrics);
        $this->assertArrayHasKey('active_webhooks', $metrics);
        $this->assertArrayHasKey('deliveries_today', $metrics);
        $this->assertArrayHasKey('success_rate', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_user_metrics(): void
    {
        User::factory()->create(['created_at' => now()]);

        Cache::forget('metrics:users');

        $metrics = $this->service->getUserMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('total_users', $metrics);
        $this->assertArrayHasKey('new_users', $metrics);
        $this->assertArrayHasKey('active_users', $metrics);
        $this->assertArrayHasKey('mfa', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_organization_metrics(): void
    {
        Organization::factory()->create(['created_at' => now()]);

        Cache::forget('metrics:organizations');

        $metrics = $this->service->getOrganizationMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('total_organizations', $metrics);
        $this->assertArrayHasKey('new_organizations', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_mfa_metrics(): void
    {
        User::factory()->create(['mfa_methods' => ['totp']]);

        Cache::forget('metrics:mfa');

        $metrics = $this->service->getMfaMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('enabled_users', $metrics);
        $this->assertArrayHasKey('usage', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_performance_metrics(): void
    {
        $metrics = $this->service->getPerformanceMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('avg_response_time_ms', $metrics);
        $this->assertArrayHasKey('cache', $metrics);
        $this->assertArrayHasKey('slow_queries_count', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_records_custom_metrics(): void
    {
        $this->service->recordMetric('test_metric', 100, ['tag' => 'test']);

        $metric = $this->service->getMetric('test_metric');

        $this->assertNotNull($metric);
        $this->assertEquals('test_metric', $metric['name']);
        $this->assertEquals(1, $metric['count']);
        $this->assertEquals(100, $metric['sum']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_caches_metrics_for_performance(): void
    {
        // First call should hit database
        $metrics1 = $this->service->getAuthenticationMetrics();

        // Second call should hit cache
        $metrics2 = $this->service->getAuthenticationMetrics();

        $this->assertEquals($metrics1, $metrics2);
    }
}
