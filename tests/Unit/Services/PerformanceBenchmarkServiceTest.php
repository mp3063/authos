<?php

namespace Tests\Unit\Services;

use App\Services\PerformanceBenchmarkService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class PerformanceBenchmarkServiceTest extends TestCase
{
    private PerformanceBenchmarkService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new PerformanceBenchmarkService;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_starts_and_stops_benchmark(): void
    {
        Log::shouldReceive('debug')->twice();

        $this->service->start('test_benchmark');

        // Simulate some work
        usleep(10000); // 10ms

        $result = $this->service->stop('test_benchmark');

        $this->assertEquals('test_benchmark', $result['name']);
        $this->assertGreaterThan(0, $result['duration_ms']);
        $this->assertArrayHasKey('memory_mb', $result);
        $this->assertArrayHasKey('peak_memory_mb', $result);
        $this->assertArrayHasKey('timestamp', $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_benchmarks_callable_function(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmark('test_function', function () {
            return 'test_result';
        });

        $this->assertEquals('test_function', $result['name']);
        $this->assertTrue($result['metadata']['success']);
        $this->assertEquals('test_result', $result['metadata']['result']);
        $this->assertGreaterThanOrEqual(0, $result['duration_ms']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_benchmark_exceptions(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmark('failing_function', function () {
            throw new \Exception('Test error');
        });

        $this->assertEquals('failing_function', $result['name']);
        $this->assertFalse($result['metadata']['success']);
        $this->assertEquals('Test error', $result['metadata']['error']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_benchmarks_database_query(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmarkQuery(
            'select_query',
            'SELECT 1 as test'
        );

        $this->assertEquals('select_query', $result['name']);
        $this->assertTrue($result['metadata']['success']);
        $this->assertEquals(1, $result['metadata']['rows']);
        $this->assertArrayHasKey('queries', $result['metadata']);
        $this->assertArrayHasKey('query_time_ms', $result['metadata']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function it_benchmarks_query_with_bindings(): void
    {
        // Mock logs - may be called by benchmark service and observers
        Log::shouldReceive('debug')->atLeast()->once();
        Log::shouldReceive('error')->zeroOrMoreTimes();

        // Create organization first to satisfy foreign key constraint
        $org = \App\Models\Organization::factory()->create();

        DB::table('users')->insert([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'hashed',
            'organization_id' => $org->id,
        ]);

        $result = $this->service->benchmarkQuery(
            'select_with_bindings',
            'SELECT * FROM users WHERE email = ?',
            ['test@example.com']
        );

        $this->assertTrue($result['metadata']['success']);
        $this->assertGreaterThanOrEqual(1, $result['metadata']['rows']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_query_errors(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmarkQuery(
            'invalid_query',
            'SELECT * FROM nonexistent_table'
        );

        $this->assertFalse($result['metadata']['success']);
        $this->assertArrayHasKey('error', $result['metadata']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_benchmarks_http_endpoint(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['data' => 'test'], 200),
        ]);

        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmarkEndpoint(
            'api_test',
            'https://example.com/api/test'
        );

        $this->assertEquals('api_test', $result['name']);
        $this->assertTrue($result['metadata']['success']);
        $this->assertEquals(200, $result['metadata']['status']);
        $this->assertArrayHasKey('response_size_kb', $result['metadata']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('httpMethodProvider')]
    public function it_benchmarks_different_http_methods(string $method): void
    {
        Http::fake([
            '*' => Http::response(['success' => true], 200),
        ]);

        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmarkEndpoint(
            "test_{$method}",
            'https://example.com/api/test',
            $method
        );

        $this->assertTrue($result['metadata']['success']);
        $this->assertEquals($method, $result['metadata']['method']);
    }

    public static function httpMethodProvider(): array
    {
        return [
            'GET' => ['GET'],
            'POST' => ['POST'],
            'PUT' => ['PUT'],
            'DELETE' => ['DELETE'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_http_errors(): void
    {
        Http::fake([
            '*' => Http::response(null, 500),
        ]);

        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmarkEndpoint(
            'failing_endpoint',
            'https://example.com/api/error'
        );

        $this->assertFalse($result['metadata']['success']);
        $this->assertEquals(500, $result['metadata']['status']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_invalid_http_method(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmarkEndpoint(
            'invalid_method',
            'https://example.com/api/test',
            'INVALID'
        );

        $this->assertFalse($result['metadata']['success']);
        $this->assertArrayHasKey('error', $result['metadata']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_runs_multiple_benchmark_iterations(): void
    {
        Log::shouldReceive('debug')->atLeast()->once();
        Log::shouldReceive('info')->once();

        $stats = $this->service->benchmarkIterations('iteration_test', function () {
            return str_repeat('x', 100);
        }, 10);

        $this->assertEquals('iteration_test', $stats['name']);
        $this->assertEquals(10, $stats['iterations']);
        $this->assertArrayHasKey('min_ms', $stats);
        $this->assertArrayHasKey('max_ms', $stats);
        $this->assertArrayHasKey('avg_ms', $stats);
        $this->assertArrayHasKey('median_ms', $stats);
        $this->assertArrayHasKey('p95_ms', $stats);
        $this->assertArrayHasKey('p99_ms', $stats);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_correct_statistics(): void
    {
        Log::shouldReceive('debug')->atLeast()->once();
        Log::shouldReceive('info')->once();

        $stats = $this->service->benchmarkIterations('stats_test', function () {
            usleep(1000); // 1ms
        }, 5);

        $this->assertGreaterThan(0, $stats['min_ms']);
        $this->assertGreaterThanOrEqual($stats['min_ms'], $stats['avg_ms']);
        $this->assertGreaterThanOrEqual($stats['avg_ms'], $stats['max_ms']);
        $this->assertGreaterThanOrEqual($stats['median_ms'], $stats['p95_ms']);
        $this->assertGreaterThanOrEqual($stats['p95_ms'], $stats['p99_ms']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_stores_benchmark_results(): void
    {
        Log::shouldReceive('debug')->times(4);

        $this->service->benchmark('test1', fn () => 'result1');
        $this->service->benchmark('test2', fn () => 'result2');

        $results = $this->service->getResults();

        $this->assertCount(2, $results);
        $this->assertEquals('test1', $results[0]['name']);
        $this->assertEquals('test2', $results[1]['name']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_generates_summary_statistics(): void
    {
        Log::shouldReceive('debug')->times(6);

        $this->service->benchmark('test1', fn () => str_repeat('x', 1000));
        $this->service->benchmark('test2', fn () => str_repeat('y', 2000));
        $this->service->benchmark('test3', fn () => str_repeat('z', 3000));

        $summary = $this->service->getSummary();

        $this->assertEquals(3, $summary['total_benchmarks']);
        $this->assertGreaterThan(0, $summary['total_duration_ms']);
        $this->assertGreaterThan(0, $summary['avg_duration_ms']);
        $this->assertGreaterThanOrEqual($summary['avg_duration_ms'], $summary['max_duration_ms']);
        $this->assertLessThanOrEqual($summary['avg_duration_ms'], $summary['min_duration_ms']);
        $this->assertArrayHasKey('total_memory_mb', $summary);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_empty_summary_with_no_results(): void
    {
        $summary = $this->service->getSummary();

        $this->assertEmpty($summary);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_resets_benchmark_results(): void
    {
        Log::shouldReceive('debug')->twice();

        $this->service->benchmark('test', fn () => 'result');

        $this->assertCount(1, $this->service->getResults());

        $this->service->reset();

        $this->assertCount(0, $this->service->getResults());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_exports_benchmark_data(): void
    {
        Log::shouldReceive('debug')->times(4);

        $this->service->benchmark('test1', fn () => 'result1');
        $this->service->benchmark('test2', fn () => 'result2');

        $export = $this->service->export();

        $this->assertArrayHasKey('summary', $export);
        $this->assertArrayHasKey('results', $export);
        $this->assertArrayHasKey('timestamp', $export);
        $this->assertCount(2, $export['results']);
        $this->assertEquals(2, $export['summary']['total_benchmarks']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_includes_metadata_in_benchmark_results(): void
    {
        Log::shouldReceive('debug')->twice();

        $metadata = [
            'custom_key' => 'custom_value',
            'iteration' => 5,
        ];

        $result = $this->service->benchmark('metadata_test', fn () => 'result', $metadata);

        $this->assertTrue($result['metadata']['success']);
        $this->assertEquals('custom_value', $result['metadata']['custom_key']);
        $this->assertEquals(5, $result['metadata']['iteration']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_memory_usage(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmark('memory_test', function () {
            $data = [];
            // Allocate more memory to ensure measurable difference
            for ($i = 0; $i < 10000; $i++) {
                $data[] = str_repeat('x', 10000);
            }

            return count($data);
        });

        $this->assertGreaterThanOrEqual(0, $result['memory_mb']);
        $this->assertGreaterThanOrEqual($result['memory_mb'], $result['peak_memory_mb']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_includes_timestamp_in_results(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmark('timestamp_test', fn () => 'result');

        $this->assertArrayHasKey('timestamp', $result);
        $this->assertMatchesRegularExpression('/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/', $result['timestamp']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_non_scalar_return_values(): void
    {
        Log::shouldReceive('debug')->twice();

        $result = $this->service->benchmark('object_test', function () {
            return new \stdClass;
        });

        $this->assertTrue($result['metadata']['success']);
        $this->assertEquals('object', $result['metadata']['result']);
    }
}
