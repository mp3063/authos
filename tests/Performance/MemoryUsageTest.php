<?php

namespace Tests\Performance;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Laravel\Passport\Passport;

class MemoryUsageTest extends PerformanceTestCase
{
    protected bool $enableQueryLog = true;

    private Organization $organization;

    private User $user;

    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->for($this->organization)->create();
        $this->user->assignRole('Organization Owner');

        Passport::actingAs($this->user);
        $this->accessToken = $this->user->createToken('Test Token')->accessToken;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function memory_per_request_meets_target(): void
    {
        User::factory()->count(50)->for($this->organization)->create();

        $samples = [];

        for ($i = 0; $i < 10; $i++) {
            $metrics = $this->measure(function () {
                return $this->withHeaders([
                    'Authorization' => "Bearer {$this->accessToken}",
                ])->getJson('/api/v1/users');
            }, "memory_test_{$i}");

            $samples[] = $metrics['memory_used_mb'];
        }

        $avgMemory = array_sum($samples) / count($samples);
        $maxMemory = max($samples);
        $peakMemory = memory_get_peak_usage(true) / 1024 / 1024;

        $this->assertMemoryUsage($avgMemory, 20, 'Average memory per request should be < 20MB');
        $this->assertMemoryUsage($maxMemory, 30, 'Max memory per request should be < 30MB');

        $this->recordBaseline('memory_per_request', [
            'avg_memory_mb' => $avgMemory,
            'max_memory_mb' => $maxMemory,
            'peak_memory_mb' => $peakMemory,
        ]);

        echo "\n✓ Memory Per Request:\n";
        echo '  Average: '.number_format($avgMemory, 2)." MB\n";
        echo '  Max: '.number_format($maxMemory, 2)." MB\n";
        echo '  Peak: '.number_format($peakMemory, 2)." MB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function no_memory_leaks_in_repeated_requests(): void
    {
        $memoryReadings = [];

        // Make 50 requests and track memory
        for ($i = 0; $i < 50; $i++) {
            $startMemory = memory_get_usage(true);

            $this->withHeaders([
                'Authorization' => "Bearer {$this->accessToken}",
            ])->getJson('/api/v1/users');

            $endMemory = memory_get_usage(true);
            $memoryReadings[] = $endMemory / 1024 / 1024;

            // Force garbage collection periodically
            if ($i % 10 === 0) {
                gc_collect_cycles();
            }
        }

        // Check if memory is growing linearly (leak indicator)
        $firstQuarter = array_slice($memoryReadings, 0, 12);
        $lastQuarter = array_slice($memoryReadings, -12);

        $avgFirst = array_sum($firstQuarter) / count($firstQuarter);
        $avgLast = array_sum($lastQuarter) / count($lastQuarter);

        $memoryGrowth = $avgLast - $avgFirst;
        $growthPercent = ($memoryGrowth / $avgFirst) * 100;

        // Memory growth should be less than 10%
        $this->assertLessThan(10, $growthPercent, 'Memory should not grow significantly over repeated requests');

        echo "\n✓ Memory Leak Detection:\n";
        echo '  First Quarter Avg: '.number_format($avgFirst, 2)." MB\n";
        echo '  Last Quarter Avg: '.number_format($avgLast, 2)." MB\n";
        echo '  Growth: '.number_format($memoryGrowth, 2).' MB ('.number_format($growthPercent, 1)."%)\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function large_dataset_memory_efficiency(): void
    {
        // Create large dataset
        User::factory()->count(1000)->for($this->organization)->create();

        $metrics = $this->measure(function () {
            return $this->withHeaders([
                'Authorization' => "Bearer {$this->accessToken}",
            ])->getJson('/api/v1/users?per_page=100');
        }, 'large_dataset');

        $memoryPerRecord = $metrics['memory_used_mb'] / 100;

        $this->assertLessThan(0.5, $memoryPerRecord, 'Memory per record should be < 0.5MB');

        echo "\n✓ Large Dataset Memory Efficiency:\n";
        echo '  Total Memory: '.number_format($metrics['memory_used_mb'], 2)." MB\n";
        echo '  Memory per Record: '.number_format($memoryPerRecord, 3)." MB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function collection_memory_usage_optimization(): void
    {
        // Test memory usage with collection chunking
        $users = User::factory()->count(500)->for($this->organization)->create();

        // Without chunking
        $startMemory = memory_get_usage(true);
        $allUsers = User::all();
        $peakWithoutChunking = memory_get_peak_usage(true);
        unset($allUsers);
        gc_collect_cycles();

        // With chunking
        $startMemory2 = memory_get_usage(true);
        User::chunk(100, function ($chunk) {
            // Process chunk
        });
        $peakWithChunking = memory_get_peak_usage(true);

        $withoutChunkingMb = ($peakWithoutChunking - $startMemory) / 1024 / 1024;
        $withChunkingMb = ($peakWithChunking - $startMemory2) / 1024 / 1024;

        $memorySaving = $withoutChunkingMb > 0
            ? (($withoutChunkingMb - $withChunkingMb) / $withoutChunkingMb) * 100
            : 0;

        echo "\n✓ Collection Chunking Memory Efficiency:\n";
        echo '  Without Chunking: '.number_format($withoutChunkingMb, 2)." MB\n";
        echo '  With Chunking: '.number_format($withChunkingMb, 2)." MB\n";
        echo '  Memory Saving: '.number_format($memorySaving, 1)."%\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function eager_loading_memory_impact(): void
    {
        $users = User::factory()->count(50)->for($this->organization)->create();
        Application::factory()->count(100)->for($this->organization)->create();

        // Assign applications to users
        foreach ($users as $user) {
            $user->applications()->attach(
                Application::inRandomOrder()->limit(3)->pluck('id')
            );
        }

        // Without eager loading
        $metrics1 = $this->measure(function () {
            $users = User::limit(50)->get();
            foreach ($users as $user) {
                $apps = $user->applications;
            }
        }, 'without_eager_loading');

        // With eager loading
        $metrics2 = $this->measure(function () {
            $users = User::with('applications')->limit(50)->get();
            foreach ($users as $user) {
                $apps = $user->applications;
            }
        }, 'with_eager_loading');

        $memorySaving = $metrics1['memory_used_mb'] - $metrics2['memory_used_mb'];

        echo "\n✓ Eager Loading Memory Impact:\n";
        echo '  Without Eager Loading: '.number_format($metrics1['memory_used_mb'], 2)." MB\n";
        echo '  With Eager Loading: '.number_format($metrics2['memory_used_mb'], 2)." MB\n";
        echo '  Memory Difference: '.number_format($memorySaving, 2)." MB\n";
        echo '  Query Count Difference: '.($metrics1['query_count'] - $metrics2['query_count'])."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function authentication_log_pagination_memory_efficiency(): void
    {
        $user = User::factory()->for($this->organization)->create();
        $app = Application::factory()->for($this->organization)->create();

        AuthenticationLog::factory()->count(1000)->create([
            'user_id' => $user->id,
            'application_id' => $app->id,
        ]);

        // Test first page
        $metrics1 = $this->measure(function () use ($user) {
            return AuthenticationLog::where('user_id', $user->id)
                ->with(['user', 'application'])
                ->paginate(50);
        }, 'page_1');

        // Test middle page
        $metrics2 = $this->measure(function () use ($user) {
            return AuthenticationLog::where('user_id', $user->id)
                ->with(['user', 'application'])
                ->paginate(50, ['*'], 'page', 10);
        }, 'page_10');

        $avgMemory = ($metrics1['memory_used_mb'] + $metrics2['memory_used_mb']) / 2;

        $this->assertMemoryUsage($avgMemory, 15, 'Pagination memory usage should be < 15MB');

        echo "\n✓ Pagination Memory Efficiency:\n";
        echo '  Page 1 Memory: '.number_format($metrics1['memory_used_mb'], 2)." MB\n";
        echo '  Page 10 Memory: '.number_format($metrics2['memory_used_mb'], 2)." MB\n";
        echo '  Average: '.number_format($avgMemory, 2)." MB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function peak_memory_under_concurrent_load_simulation(): void
    {
        User::factory()->count(100)->for($this->organization)->create();

        $peakMemories = [];

        // Simulate 10 concurrent requests
        for ($i = 0; $i < 10; $i++) {
            $startPeak = memory_get_peak_usage(true);

            $this->withHeaders([
                'Authorization' => "Bearer {$this->accessToken}",
            ])->getJson('/api/v1/users');

            $peakMemories[] = (memory_get_peak_usage(true) - $startPeak) / 1024 / 1024;
        }

        $avgPeak = array_sum($peakMemories) / count($peakMemories);
        $maxPeak = max($peakMemories);

        $this->assertMemoryUsage($maxPeak, 50, 'Peak memory under load should be < 50MB');

        echo "\n✓ Peak Memory Under Load:\n";
        echo '  Average Peak: '.number_format($avgPeak, 2)." MB\n";
        echo '  Max Peak: '.number_format($maxPeak, 2)." MB\n";
    }
}
