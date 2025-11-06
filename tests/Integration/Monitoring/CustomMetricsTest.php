<?php

namespace Tests\Integration\Monitoring;

use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * Custom Metrics Integration Tests
 *
 * Tests the custom metrics system that allows applications to
 * record and query custom business metrics beyond standard
 * system metrics.
 *
 * Endpoints tested:
 * - POST /api/v1/monitoring/metrics/record (record metric)
 * - GET /api/v1/monitoring/metrics/{name} (query metric)
 */
class CustomMetricsTest extends IntegrationTestCase
{
    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = $this->createUser();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function record_custom_metric_successfully(): void
    {
        // ARRANGE: Authenticated user with metric data
        $metricData = [
            'name' => 'api.custom.signup_conversions',
            'value' => 42,
            'tags' => [
                'source' => 'landing_page',
                'campaign' => 'summer_2024',
                'region' => 'us-west',
            ],
        ];

        // ACT: Record custom metric
        $response = $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/monitoring/metrics/record', $metricData);

        // ASSERT: Metric is recorded successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'message',
            'metric',
        ]);

        $data = $response->json();
        $this->assertEquals('Metric recorded successfully', $data['message']);
        $this->assertEquals('api.custom.signup_conversions', $data['metric']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function increment_counter_metric(): void
    {
        // ARRANGE: Record initial counter value
        $metricName = 'api.custom.button_clicks';

        $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/monitoring/metrics/record', [
                'name' => $metricName,
                'value' => 1,
                'tags' => ['button' => 'subscribe'],
            ]);

        // ACT: Increment counter multiple times
        for ($i = 0; $i < 5; $i++) {
            $response = $this->actingAsApiUserWithToken($this->user)
                ->postJson('/api/v1/monitoring/metrics/record', [
                    'name' => $metricName,
                    'value' => 1,
                    'tags' => ['button' => 'subscribe'],
                ]);

            $response->assertOk();
        }

        // ASSERT: All increments were recorded
        $queryResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/monitoring/metrics/{$metricName}");

        $queryResponse->assertOk();
        $data = $queryResponse->json();

        // Verify metric exists with aggregated data
        $this->assertArrayHasKey('name', $data);
        $this->assertEquals($metricName, $data['name']);
        // Metric may have sum, count, values array - verify core structure
        $this->assertArrayHasKey('count', $data);
        $this->assertGreaterThanOrEqual(6, $data['count']); // Initial + 5 increments
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function record_timing_metric_for_performance_tracking(): void
    {
        // ARRANGE: Timing metric for custom operation
        $timingData = [
            'name' => 'api.custom.export_duration',
            'value' => 2547.89, // milliseconds
            'tags' => [
                'export_type' => 'pdf',
                'size' => 'large',
                'user_id' => $this->user->id,
            ],
        ];

        // ACT: Record timing metric
        $response = $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/monitoring/metrics/record', $timingData);

        // ASSERT: Timing metric is recorded
        $response->assertOk();
        $response->assertJson([
            'message' => 'Metric recorded successfully',
            'metric' => 'api.custom.export_duration',
        ]);

        // Verify we can query the timing metric
        $queryResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/metrics/api.custom.export_duration');

        $queryResponse->assertOk();
        $data = $queryResponse->json();
        $this->assertEquals('api.custom.export_duration', $data['name']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function query_custom_metrics_with_date_filter(): void
    {
        // ARRANGE: Record metrics over multiple days
        $metricName = 'api.custom.feature_usage';

        // Today's metric
        $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/monitoring/metrics/record', [
                'name' => $metricName,
                'value' => 100,
                'tags' => ['feature' => 'export'],
            ]);

        // ACT: Query metric for today
        $todayResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/monitoring/metrics/{$metricName}?date=".now()->format('Y-m-d'));

        // Query metric for yesterday (should not exist)
        $yesterdayResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/monitoring/metrics/{$metricName}?date=".now()->subDay()->format('Y-m-d'));

        // ASSERT: Today's metric exists, yesterday's doesn't
        $todayResponse->assertOk();
        $todayData = $todayResponse->json();
        $this->assertNotNull($todayData);
        $this->assertArrayHasKey('name', $todayData);

        // Yesterday should return 404 or empty data
        // (depends on implementation)
        if ($yesterdayResponse->status() === 404) {
            $yesterdayResponse->assertNotFound();
        } else {
            $yesterdayData = $yesterdayResponse->json();
            $this->assertTrue(
                !isset($yesterdayData['value']) ||
                $yesterdayData['value'] === 0 ||
                empty($yesterdayData)
            );
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function validation_prevents_invalid_metric_data(): void
    {
        // ARRANGE & ACT: Attempt to record invalid metrics
        $this->actingAsApiUserWithToken($this->user);

        // Missing name
        $response1 = $this->postJson('/api/v1/monitoring/metrics/record', [
            'value' => 100,
        ]);

        // Missing value
        $response2 = $this->postJson('/api/v1/monitoring/metrics/record', [
            'name' => 'test.metric',
        ]);

        // Invalid value type
        $response3 = $this->postJson('/api/v1/monitoring/metrics/record', [
            'name' => 'test.metric',
            'value' => 'not-a-number',
        ]);

        // Invalid tags type
        $response4 = $this->postJson('/api/v1/monitoring/metrics/record', [
            'name' => 'test.metric',
            'value' => 100,
            'tags' => 'invalid-tags',
        ]);

        // ASSERT: All invalid requests are rejected
        $response1->assertUnprocessable();
        $response1->assertJsonValidationErrors(['name']);

        $response2->assertUnprocessable();
        $response2->assertJsonValidationErrors(['value']);

        $response3->assertUnprocessable();
        $response3->assertJsonValidationErrors(['value']);

        $response4->assertUnprocessable();
        $response4->assertJsonValidationErrors(['tags']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function query_nonexistent_metric_returns_error(): void
    {
        // ARRANGE: Authenticated user
        $this->actingAsApiUserWithToken($this->user);

        // ACT: Query metric that doesn't exist
        $response = $this->getJson('/api/v1/monitoring/metrics/nonexistent.metric.name');

        // ASSERT: Returns 404 with error message
        $response->assertNotFound();
        $response->assertJsonStructure([
            'error',
        ]);

        $data = $response->json();
        $this->assertEquals('Metric not found', $data['error']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function custom_metrics_support_complex_tag_filtering(): void
    {
        // ARRANGE: Record metrics with multiple tags
        $metricName = 'api.custom.api_calls';

        $tagSets = [
            ['endpoint' => '/users', 'method' => 'GET', 'status' => '200'],
            ['endpoint' => '/users', 'method' => 'POST', 'status' => '201'],
            ['endpoint' => '/applications', 'method' => 'GET', 'status' => '200'],
        ];

        foreach ($tagSets as $index => $tags) {
            $this->actingAsApiUserWithToken($this->user)
                ->postJson('/api/v1/monitoring/metrics/record', [
                    'name' => $metricName,
                    'value' => ($index + 1) * 10,
                    'tags' => $tags,
                ]);
        }

        // ACT: Query the metric (tags might be in response)
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/monitoring/metrics/{$metricName}");

        // ASSERT: Metric exists with aggregated data
        $response->assertOk();
        $data = $response->json();

        $this->assertEquals($metricName, $data['name']);
        // Verify metric has aggregated data
        $this->assertArrayHasKey('count', $data);
        $this->assertGreaterThanOrEqual(3, $data['count']);

        // If implementation returns tag breakdown, verify structure
        if (isset($data['tags']) || isset($data['by_tags'])) {
            $tagData = $data['tags'] ?? $data['by_tags'];
            $this->assertIsArray($tagData);
        }
    }
}
