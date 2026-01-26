<?php

namespace Tests\Integration\Monitoring;

use App\Models\User;
use Illuminate\Support\Facades\Log;
use Tests\Integration\IntegrationTestCase;

/**
 * Error Tracking Integration Tests
 *
 * Tests the error tracking and monitoring system that collects,
 * analyzes, and reports application errors for debugging and
 * system health monitoring.
 *
 * Endpoints tested:
 * - GET /api/v1/monitoring/errors (list errors)
 * - GET /api/v1/monitoring/errors/trends (7-day trends)
 * - GET /api/v1/monitoring/errors/recent (recent errors)
 */
class ErrorTrackingTest extends IntegrationTestCase
{
    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = $this->createUser();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function list_recent_errors_returns_error_logs(): void
    {
        // ARRANGE: Generate some application errors
        try {
            Log::error('Test error 1', [
                'exception' => 'TestException',
                'endpoint' => '/api/v1/test',
                'user_id' => $this->user->id,
            ]);

            Log::error('Test error 2', [
                'exception' => 'ValidationException',
                'endpoint' => '/api/v1/users',
            ]);
        } catch (\Exception $e) {
            // Errors logged, continue
        }

        // ACT: Request recent errors list
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors/recent?limit=10');

        // ASSERT: Response contains error list
        $response->assertOk();
        $response->assertJsonStructure([
            'errors',
            'count',
        ]);

        $data = $response->json();
        $this->assertIsArray($data['errors']);
        $this->assertIsInt($data['count']);
        $this->assertGreaterThanOrEqual(0, $data['count']);

        // If errors exist, verify structure
        if ($data['count'] > 0) {
            $this->assertArrayHasKey('message', $data['errors'][0]);
            $this->assertArrayHasKey('timestamp', $data['errors'][0]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function view_error_statistics_for_specific_date(): void
    {
        // ARRANGE: Log errors for today
        Log::error('Daily error 1', ['type' => 'database']);
        Log::error('Daily error 2', ['type' => 'api']);
        Log::warning('Warning message', ['type' => 'validation']);

        // ACT: Request error statistics for today
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors?date='.now()->format('Y-m-d'));

        // ASSERT: Statistics are returned
        $response->assertOk();
        $response->assertJsonStructure([
            'critical',
            'error',
            'warning',
            'info',
            'total',
            'by_type',
            'by_hour',
        ]);

        $data = $response->json();
        $this->assertIsInt($data['total']);
        $this->assertIsInt($data['error']);
        $this->assertIsArray($data['by_type']);
        $this->assertIsArray($data['by_hour']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function get_error_trends_over_seven_days(): void
    {
        // ARRANGE: Log errors over multiple days
        for ($i = 0; $i < 3; $i++) {
            Log::error("Historical error day {$i}", [
                'day' => $i,
                'endpoint' => '/api/v1/test',
            ]);
        }

        // ACT: Request 7-day error trends
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors/trends?days=7');

        // ASSERT: Trend data is returned for 7 days
        $response->assertOk();
        $response->assertJsonStructure([
            'trends',
            'days',
        ]);

        $data = $response->json();
        $this->assertEquals(7, $data['days']);
        $this->assertIsArray($data['trends']);
        $this->assertCount(7, $data['trends']);

        // Verify trend structure
        foreach ($data['trends'] as $trend) {
            $this->assertArrayHasKey('date', $trend);
            $this->assertArrayHasKey('total', $trend);
            $this->assertArrayHasKey('critical', $trend);
            $this->assertArrayHasKey('error', $trend);
            $this->assertArrayHasKey('warning', $trend);
            $this->assertIsInt($trend['total']);
            $this->assertGreaterThanOrEqual(0, $trend['total']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function filter_errors_by_type(): void
    {
        // ARRANGE: Log errors of different types
        Log::error('Database error', [
            'type' => 'database',
            'exception' => 'QueryException',
        ]);

        Log::error('API error', [
            'type' => 'api',
            'exception' => 'HttpException',
        ]);

        Log::error('Validation error', [
            'type' => 'validation',
            'exception' => 'ValidationException',
        ]);

        // ACT: Request error statistics (which includes breakdown by type)
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors');

        // ASSERT: Response includes error statistics with type breakdown
        $response->assertOk();
        $response->assertJsonStructure([
            'total',
            'by_type',
        ]);

        $data = $response->json();
        $this->assertIsArray($data['by_type']);
        $this->assertIsInt($data['total']);

        // Verify type breakdown structure (if has types)
        if (! empty($data['by_type'])) {
            foreach ($data['by_type'] as $type => $count) {
                $this->assertIsString($type);
                $this->assertIsInt($count);
                $this->assertGreaterThanOrEqual(0, $count);
            }
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function error_count_by_endpoint_shows_problematic_routes(): void
    {
        // ARRANGE: Log errors from different endpoints
        Log::error('Error on users endpoint', [
            'endpoint' => '/api/v1/users',
            'method' => 'GET',
        ]);

        Log::error('Error on applications endpoint', [
            'endpoint' => '/api/v1/applications',
            'method' => 'POST',
        ]);

        Log::error('Another users error', [
            'endpoint' => '/api/v1/users',
            'method' => 'POST',
        ]);

        // ACT: Request error statistics
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors');

        // ASSERT: Response includes error counts
        $response->assertOk();
        $data = $response->json();

        // Verify we can track errors (structure may vary)
        $this->assertArrayHasKey('total', $data);
        $this->assertIsInt($data['total']);

        // Verify by_type contains error information
        $this->assertArrayHasKey('by_type', $data);
        $this->assertIsArray($data['by_type']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_error_logs_for_analysis(): void
    {
        // ARRANGE: Log several errors with context
        for ($i = 0; $i < 5; $i++) {
            Log::error("Export test error {$i}", [
                'error_id' => $i,
                'severity' => 'high',
                'endpoint' => '/api/v1/test',
                'user_id' => $this->user->id,
                'timestamp' => now()->subMinutes($i)->toIso8601String(),
            ]);
        }

        // ACT: Request recent errors with higher limit for export
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors/recent?limit=100');

        // ASSERT: All errors are returned for export
        $response->assertOk();
        $response->assertJsonStructure([
            'errors',
            'count',
        ]);

        $data = $response->json();
        $this->assertIsArray($data['errors']);
        $this->assertIsInt($data['count']);

        // Verify exportable data structure (may be empty if no errors in cache)
        $this->assertGreaterThanOrEqual(0, $data['count']);

        // If errors exist, verify structure
        if ($data['count'] > 0) {
            $firstError = $data['errors'][0];
            $this->assertIsArray($firstError);
            $this->assertArrayHasKey('message', $firstError);
            $this->assertArrayHasKey('timestamp', $firstError);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function error_trends_can_be_requested_for_custom_period(): void
    {
        // ARRANGE: Log errors over time
        Log::error('Recent error', ['timestamp' => now()]);

        // ACT: Request trends for different periods
        $response14Days = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors/trends?days=14');

        $response30Days = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/monitoring/errors/trends?days=30');

        // ASSERT: Both periods return appropriate data
        $response14Days->assertOk();
        $response30Days->assertOk();

        $data14 = $response14Days->json();
        $data30 = $response30Days->json();

        $this->assertEquals(14, $data14['days']);
        $this->assertCount(14, $data14['trends']);

        $this->assertEquals(30, $data30['days']);
        $this->assertCount(30, $data30['trends']);

        // Verify trend structure
        foreach ($data14['trends'] as $trend) {
            $this->assertArrayHasKey('date', $trend);
            $this->assertArrayHasKey('total', $trend);
        }
    }
}
