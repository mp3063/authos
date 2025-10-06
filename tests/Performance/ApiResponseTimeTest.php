<?php

namespace Tests\Performance;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

class ApiResponseTimeTest extends PerformanceTestCase
{
    protected bool $enableQueryLog = true;

    private Organization $organization;

    private User $user;

    private Application $application;

    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();

        // Create test data
        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->for($this->organization)->create([
            'password' => Hash::make('password123'),
        ]);
        $this->user->assignRole('Organization Owner');

        $this->application = Application::factory()->for($this->organization)->create();

        // Generate access token for authenticated requests
        Passport::actingAs($this->user);
        $this->accessToken = $this->user->createToken('Test Token')->accessToken;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function authentication_login_meets_performance_target(): void
    {
        $samples = [];

        // Run multiple samples to get p95
        for ($i = 0; $i < 20; $i++) {
            $this->startMeasuring("login_{$i}");

            $response = $this->postJson('/api/v1/auth/login', [
                'email' => $this->user->email,
                'password' => 'password123',
            ]);

            $metrics = $this->stopMeasuring("login_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);
        $avgQueryCount = array_sum(array_column($this->metrics, 'query_count')) / 20;

        $this->assertResponseTime($p95, 100, 'Login p95 response time should be < 100ms');
        $this->assertQueryCount((int) $avgQueryCount, 10, 'Login should use < 10 queries');

        // Record baseline
        $this->recordBaseline('auth_login', [
            'p95_response_time_ms' => $p95,
            'avg_query_count' => $avgQueryCount,
        ]);

        echo "\n✓ Authentication Login Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
        echo '  Avg Query Count: '.number_format($avgQueryCount, 1)."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function authentication_register_meets_performance_target(): void
    {
        $samples = [];

        for ($i = 0; $i < 10; $i++) {
            $this->startMeasuring("register_{$i}");

            $response = $this->postJson('/api/v1/auth/register', [
                'name' => "Test User {$i}",
                'email' => "test{$i}@example.com",
                'password' => 'password123',
                'password_confirmation' => 'password123',
                'organization_name' => "Test Org {$i}",
            ]);

            $metrics = $this->stopMeasuring("register_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(201);
        }

        $p95 = $this->calculatePercentile($samples, 95);

        $this->assertResponseTime($p95, 150, 'Register p95 response time should be < 150ms');

        echo "\n✓ Authentication Register Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_list_endpoint_meets_performance_target(): void
    {
        // Create additional users for testing
        User::factory()->count(50)->for($this->organization)->create();

        $samples = [];

        for ($i = 0; $i < 20; $i++) {
            $this->startMeasuring("user_list_{$i}");

            $response = $this->getJson('/api/v1/users', [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);

            $metrics = $this->stopMeasuring("user_list_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);
        $avgQueryCount = array_sum(array_column($this->metrics, 'query_count')) / 20;

        $this->assertResponseTime($p95, 150, 'User list p95 response time should be < 150ms');
        $this->assertQueryCount((int) $avgQueryCount, 10, 'User list should use < 10 queries');

        $this->recordBaseline('user_list', [
            'p95_response_time_ms' => $p95,
            'avg_query_count' => $avgQueryCount,
        ]);

        echo "\n✓ User List Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
        echo '  Avg Query Count: '.number_format($avgQueryCount, 1)."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_show_endpoint_meets_performance_target(): void
    {
        $samples = [];

        for ($i = 0; $i < 20; $i++) {
            $this->startMeasuring("user_show_{$i}");

            $response = $this->getJson("/api/v1/users/{$this->user->id}", [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);

            $metrics = $this->stopMeasuring("user_show_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);
        $avgQueryCount = array_sum(array_column($this->metrics, 'query_count')) / 20;

        $this->assertResponseTime($p95, 100, 'User show p95 response time should be < 100ms');
        $this->assertQueryCount((int) $avgQueryCount, 5, 'User show should use < 5 queries');

        echo "\n✓ User Show Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
        echo '  Avg Query Count: '.number_format($avgQueryCount, 1)."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function oauth_token_generation_meets_performance_target(): void
    {
        $samples = [];

        for ($i = 0; $i < 20; $i++) {
            $this->startMeasuring("oauth_token_{$i}");

            $response = $this->postJson('/api/v1/oauth/token', [
                'grant_type' => 'password',
                'client_id' => $this->application->client_id,
                'client_secret' => $this->application->client_secret,
                'username' => $this->user->email,
                'password' => 'password123',
            ]);

            $metrics = $this->stopMeasuring("oauth_token_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);

        $this->assertResponseTime($p95, 200, 'OAuth token generation p95 should be < 200ms');

        $this->recordBaseline('oauth_token', [
            'p95_response_time_ms' => $p95,
        ]);

        echo "\n✓ OAuth Token Generation Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function application_list_endpoint_meets_performance_target(): void
    {
        // Create additional applications
        Application::factory()->count(20)->for($this->organization)->create();

        $samples = [];

        for ($i = 0; $i < 20; $i++) {
            $this->startMeasuring("app_list_{$i}");

            $response = $this->getJson('/api/v1/applications', [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);

            $metrics = $this->stopMeasuring("app_list_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);
        $avgQueryCount = array_sum(array_column($this->metrics, 'query_count')) / 20;

        $this->assertResponseTime($p95, 150, 'Application list p95 should be < 150ms');
        $this->assertQueryCount((int) $avgQueryCount, 10, 'Application list should use < 10 queries');

        echo "\n✓ Application List Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
        echo '  Avg Query Count: '.number_format($avgQueryCount, 1)."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function organization_statistics_endpoint_meets_performance_target(): void
    {
        // Create data for statistics
        User::factory()->count(100)->for($this->organization)->create();
        Application::factory()->count(30)->for($this->organization)->create();

        $samples = [];

        for ($i = 0; $i < 10; $i++) {
            $this->startMeasuring("org_stats_{$i}");

            $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/statistics", [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);

            $metrics = $this->stopMeasuring("org_stats_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);
        $avgQueryCount = array_sum(array_column($this->metrics, 'query_count')) / 10;

        $this->assertResponseTime($p95, 200, 'Organization statistics p95 should be < 200ms');

        echo "\n✓ Organization Statistics Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
        echo '  Avg Query Count: '.number_format($avgQueryCount, 1)."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function profile_endpoint_meets_performance_target(): void
    {
        $samples = [];

        for ($i = 0; $i < 20; $i++) {
            $this->startMeasuring("profile_{$i}");

            $response = $this->getJson('/api/v1/profile', [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);

            $metrics = $this->stopMeasuring("profile_{$i}");
            $samples[] = $metrics['duration_ms'];

            $response->assertStatus(200);
        }

        $p95 = $this->calculatePercentile($samples, 95);
        $avgQueryCount = array_sum(array_column($this->metrics, 'query_count')) / 20;

        $this->assertResponseTime($p95, 100, 'Profile p95 response time should be < 100ms');
        $this->assertQueryCount((int) $avgQueryCount, 5, 'Profile should use < 5 queries');

        echo "\n✓ Profile Endpoint Performance:\n";
        echo '  P95 Response Time: '.number_format($p95, 2)." ms\n";
        echo '  Avg Query Count: '.number_format($avgQueryCount, 1)."\n";
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
