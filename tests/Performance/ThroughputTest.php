<?php

namespace Tests\Performance;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

class ThroughputTest extends PerformanceTestCase
{
    protected bool $enableQueryLog = true;

    private Organization $organization;

    private User $user;

    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        // Use TestCase helper to properly create user with role
        // Set password explicitly for login tests
        $this->user = $this->createUser([
            'organization_id' => $this->organization->id,
            'password' => Hash::make('password123'),
        ], 'Organization Owner');

        Passport::actingAs($this->user, ['*']);
        $this->accessToken = $this->user->createToken('Test Token', ['*'])->accessToken;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function authentication_requests_per_second(): void
    {
        $requests = 50;
        $startTime = microtime(true);

        for ($i = 0; $i < $requests; $i++) {
            $this->postJson('/api/v1/auth/login', [
                'email' => $this->user->email,
                'password' => 'password123',
            ])->assertStatus(200);
        }

        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $rps = $requests / $duration;

        $this->assertGreaterThan(10, $rps, 'Authentication throughput should be > 10 req/s');

        $this->recordBaseline('auth_throughput', [
            'requests' => $requests,
            'duration_seconds' => $duration,
            'requests_per_second' => $rps,
        ]);

        echo "\n✓ Authentication Throughput:\n";
        echo "  Total Requests: {$requests}\n";
        echo '  Duration: '.number_format($duration, 2)." seconds\n";
        echo '  Throughput: '.number_format($rps, 2)." req/s\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function api_read_requests_per_second(): void
    {
        User::factory()->count(100)->for($this->organization)->create();

        $requests = 100;
        $startTime = microtime(true);

        for ($i = 0; $i < $requests; $i++) {
            $this->withHeader('Authorization', "Bearer {$this->accessToken}")
                ->getJson('/api/v1/users')
                ->assertStatus(200);
        }

        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $rps = $requests / $duration;

        $this->assertGreaterThan(20, $rps, 'Read API throughput should be > 20 req/s');

        $this->recordBaseline('read_api_throughput', [
            'requests' => $requests,
            'duration_seconds' => $duration,
            'requests_per_second' => $rps,
        ]);

        echo "\n✓ API Read Throughput:\n";
        echo "  Total Requests: {$requests}\n";
        echo '  Duration: '.number_format($duration, 2)." seconds\n";
        echo '  Throughput: '.number_format($rps, 2)." req/s\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function oauth_token_generation_rate(): void
    {
        $app = Application::factory()->for($this->organization)->create();

        $tokens = 30;
        $startTime = microtime(true);

        for ($i = 0; $i < $tokens; $i++) {
            $this->postJson('/oauth/token', [
                'grant_type' => 'password',
                'client_id' => $app->client_id,
                'client_secret' => $app->client_secret,
                'username' => $this->user->email,
                'password' => 'password123',
            ])->assertStatus(200);
        }

        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $tokensPerSecond = $tokens / $duration;

        $this->assertGreaterThan(5, $tokensPerSecond, 'Token generation rate should be > 5 tokens/s');

        $this->recordBaseline('oauth_token_rate', [
            'tokens_generated' => $tokens,
            'duration_seconds' => $duration,
            'tokens_per_second' => $tokensPerSecond,
        ]);

        echo "\n✓ OAuth Token Generation Rate:\n";
        echo "  Tokens Generated: {$tokens}\n";
        echo '  Duration: '.number_format($duration, 2)." seconds\n";
        echo '  Rate: '.number_format($tokensPerSecond, 2)." tokens/s\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_creation_rate(): void
    {
        $users = 50;
        $startTime = microtime(true);

        for ($i = 0; $i < $users; $i++) {
            $this->withHeader('Authorization', "Bearer {$this->accessToken}")
                ->postJson('/api/v1/users', [
                    'name' => "Test User {$i}",
                    'email' => "throughput{$i}@example.com",
                    'password' => 'password123',
                    'password_confirmation' => 'password123',
                    'organization_id' => $this->organization->id,
                ])->assertStatus(201);
        }

        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $usersPerSecond = $users / $duration;

        $this->assertGreaterThan(5, $usersPerSecond, 'User creation rate should be > 5 users/s');

        echo "\n✓ User Creation Rate:\n";
        echo "  Users Created: {$users}\n";
        echo '  Duration: '.number_format($duration, 2)." seconds\n";
        echo '  Rate: '.number_format($usersPerSecond, 2)." users/s\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function sustained_load_over_time(): void
    {
        $duration = 10; // seconds
        $endTime = time() + $duration;
        $requestCount = 0;
        $samples = [];

        while (time() < $endTime) {
            $startRequest = microtime(true);

            $this->withHeader('Authorization', "Bearer {$this->accessToken}")
                ->getJson('/api/v1/users')
                ->assertStatus(200);

            $requestTime = (microtime(true) - $startRequest) * 1000;
            $samples[] = $requestTime;
            $requestCount++;
        }

        $avgResponseTime = array_sum($samples) / count($samples);
        $p95ResponseTime = $this->calculatePercentile($samples, 95);
        $throughput = $requestCount / $duration;

        $this->assertGreaterThan(10, $throughput, 'Sustained throughput should be > 10 req/s');
        $this->assertLessThan(200, $p95ResponseTime, 'P95 response time under load should be < 200ms');

        echo "\n✓ Sustained Load Performance:\n";
        echo "  Duration: {$duration} seconds\n";
        echo "  Total Requests: {$requestCount}\n";
        echo '  Throughput: '.number_format($throughput, 2)." req/s\n";
        echo '  Avg Response Time: '.number_format($avgResponseTime, 2)." ms\n";
        echo '  P95 Response Time: '.number_format($p95ResponseTime, 2)." ms\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function concurrent_user_operations(): void
    {
        $operations = 50;
        $results = [];

        $startTime = microtime(true);

        // Simulate concurrent operations
        for ($i = 0; $i < $operations; $i++) {
            $opStart = microtime(true);

            // Mix of read and write operations
            if ($i % 3 === 0) {
                // Create
                $this->postJson('/api/v1/users', [
                    'name' => "Concurrent User {$i}",
                    'email' => "concurrent{$i}@example.com",
                    'password' => 'password123',
                    'password_confirmation' => 'password123',
                    'organization_id' => $this->organization->id,
                ], [
                    'Authorization' => "Bearer {$this->accessToken}",
                ]);
            } else {
                // Read
                $this->getJson('/api/v1/users', [
                    'Authorization' => "Bearer {$this->accessToken}",
                ]);
            }

            $results[] = (microtime(true) - $opStart) * 1000;
        }

        $endTime = microtime(true);
        $totalDuration = $endTime - $startTime;
        $throughput = $operations / $totalDuration;
        $avgResponseTime = array_sum($results) / count($results);

        echo "\n✓ Concurrent Operations Performance:\n";
        echo "  Total Operations: {$operations}\n";
        echo '  Duration: '.number_format($totalDuration, 2)." seconds\n";
        echo '  Throughput: '.number_format($throughput, 2)." ops/s\n";
        echo '  Avg Response Time: '.number_format($avgResponseTime, 2)." ms\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function database_write_throughput(): void
    {
        $writes = 100;
        $startTime = microtime(true);

        for ($i = 0; $i < $writes; $i++) {
            User::factory()->for($this->organization)->create([
                'email' => "dbwrite{$i}@example.com",
            ]);
        }

        $endTime = microtime(true);
        $duration = $endTime - $startTime;
        $writesPerSecond = $writes / $duration;

        $this->assertGreaterThan(50, $writesPerSecond, 'Database write throughput should be > 50 writes/s');

        echo "\n✓ Database Write Throughput:\n";
        echo "  Total Writes: {$writes}\n";
        echo '  Duration: '.number_format($duration, 2)." seconds\n";
        echo '  Throughput: '.number_format($writesPerSecond, 2)." writes/s\n";
    }

    /**
     * Calculate percentile from array of values
     */
    private function calculatePercentile(array $values, float $percentile): float
    {
        sort($values);
        $index = ($percentile / 100) * count($values);
        $lower = floor($index);
        $upper = ceil($index);

        if ($lower === $upper) {
            return $values[(int) $lower];
        }

        $fraction = $index - $lower;

        return $values[(int) $lower] * (1 - $fraction) + $values[(int) $upper] * $fraction;
    }
}
