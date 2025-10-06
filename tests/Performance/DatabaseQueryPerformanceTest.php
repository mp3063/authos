<?php

namespace Tests\Performance;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class DatabaseQueryPerformanceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Clear and prepare database for performance tests
        Artisan::call('migrate:fresh', ['--seed' => true, '--env' => 'testing']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_query_with_eager_loading_performs_efficiently(): void
    {
        $org = Organization::factory()->create();
        User::factory()->count(10)->for($org)->create();

        DB::enableQueryLog();

        $startTime = microtime(true);

        // Query with eager loading
        $users = User::with(['organization', 'roles', 'applications'])
            ->limit(10)
            ->get();

        $endTime = microtime(true);
        $queryLog = DB::getQueryLog();
        DB::disableQueryLog();

        $duration = ($endTime - $startTime) * 1000;
        $queryCount = count($queryLog);

        // Assertions
        $this->assertLessThan(100, $duration, 'Query should execute in less than 100ms');
        $this->assertLessThan(10, $queryCount, 'Should use less than 10 queries with eager loading');
        $this->assertCount(10, $users);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function authentication_log_pagination_performs_efficiently(): void
    {
        $org = Organization::factory()->create();
        $user = User::factory()->for($org)->create();
        $app = Application::factory()->for($org)->create();

        AuthenticationLog::factory()->count(100)->create([
            'user_id' => $user->id,
            'application_id' => $app->id,
        ]);

        DB::enableQueryLog();

        $startTime = microtime(true);

        $logs = AuthenticationLog::with(['user', 'application'])
            ->orderBy('created_at', 'desc')
            ->paginate(15);

        $endTime = microtime(true);
        $queryLog = DB::getQueryLog();
        DB::disableQueryLog();

        $duration = ($endTime - $startTime) * 1000;
        $queryCount = count($queryLog);

        $this->assertLessThan(100, $duration, 'Pagination should execute in less than 100ms');
        $this->assertLessThan(5, $queryCount, 'Should use less than 5 queries');
        $this->assertCount(15, $logs);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function organization_statistics_query_performs_efficiently(): void
    {
        $org = Organization::factory()->create();
        User::factory()->count(50)->for($org)->create();
        Application::factory()->count(20)->for($org)->create();

        $startTime = microtime(true);

        $stats = $org->getStatistics();

        $endTime = microtime(true);
        $duration = ($endTime - $startTime) * 1000;

        $this->assertLessThan(200, $duration, 'Statistics query should execute in less than 200ms');
        $this->assertArrayHasKey('users_count', $stats);
        $this->assertArrayHasKey('applications_count', $stats);
        $this->assertEquals(50, $stats['users_count']);
        $this->assertEquals(20, $stats['applications_count']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_operations_perform_efficiently(): void
    {
        $org = Organization::factory()->create();

        $startTime = microtime(true);

        // Bulk insert users
        $users = User::factory()->count(100)->for($org)->create();

        $endTime = microtime(true);
        $duration = ($endTime - $startTime) * 1000;

        $this->assertLessThan(2000, $duration, 'Creating 100 users should take less than 2 seconds');
        $this->assertCount(100, $users);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function complex_filtering_query_performs_efficiently(): void
    {
        $org = Organization::factory()->create();
        User::factory()->count(50)->for($org)->create([
            'is_active' => true,
        ]);
        User::factory()->count(50)->for($org)->create([
            'is_active' => false,
        ]);

        DB::enableQueryLog();

        $startTime = microtime(true);

        $activeUsers = User::where('organization_id', $org->id)
            ->where('is_active', true)
            ->with('roles')
            ->get();

        $endTime = microtime(true);
        $queryLog = DB::getQueryLog();
        DB::disableQueryLog();

        $duration = ($endTime - $startTime) * 1000;

        $this->assertLessThan(100, $duration, 'Filtered query should execute in less than 100ms');
        $this->assertCount(50, $activeUsers);
        $this->assertLessThan(5, count($queryLog), 'Should use less than 5 queries');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function aggregate_queries_perform_efficiently(): void
    {
        Organization::factory()->count(20)->create();
        User::factory()->count(100)->create();
        Application::factory()->count(50)->create();

        $startTime = microtime(true);

        $counts = [
            'organizations' => Organization::count(),
            'users' => User::count(),
            'applications' => Application::count(),
            'active_users' => User::where('is_active', true)->count(),
        ];

        $endTime = microtime(true);
        $duration = ($endTime - $startTime) * 1000;

        $this->assertLessThan(200, $duration, 'All aggregate queries should execute in less than 200ms');
        $this->assertEquals(20, $counts['organizations']);
        $this->assertEquals(100, $counts['users']);
        $this->assertEquals(50, $counts['applications']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function no_n_plus_one_queries_in_user_list(): void
    {
        $org = Organization::factory()->create();
        $users = User::factory()->count(20)->for($org)->create();

        foreach ($users as $user) {
            $user->assignRole('Organization Owner');
        }

        DB::enableQueryLog();

        // Simulate controller behavior
        $result = User::with(['roles', 'organization', 'applications'])
            ->where('organization_id', $org->id)
            ->get();

        $queryLog = DB::getQueryLog();
        DB::disableQueryLog();

        $queryCount = count($queryLog);

        // With proper eager loading, we should have:
        // 1. Main query for users
        // 2. Query for roles
        // 3. Query for organization
        // 4. Query for applications
        // Total: ~4 queries regardless of number of users
        $this->assertLessThan(10, $queryCount, 'Should avoid N+1 queries with eager loading');
        $this->assertCount(20, $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function index_usage_improves_query_performance(): void
    {
        $org = Organization::factory()->create();
        User::factory()->count(100)->for($org)->create();

        // Query using indexed column (organization_id)
        $startIndexed = microtime(true);
        $indexedResults = User::where('organization_id', $org->id)->get();
        $indexedTime = (microtime(true) - $startIndexed) * 1000;

        // Query using indexed column (email)
        $testEmail = User::first()->email;
        $startEmail = microtime(true);
        $emailResults = User::where('email', $testEmail)->first();
        $emailTime = (microtime(true) - $startEmail) * 1000;

        $this->assertLessThan(50, $indexedTime, 'Indexed query should be very fast');
        $this->assertLessThan(20, $emailTime, 'Unique indexed query should be very fast');
        $this->assertCount(100, $indexedResults);
        $this->assertNotNull($emailResults);
    }
}
