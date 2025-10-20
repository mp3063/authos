<?php

namespace Tests\Performance;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;

class BulkOperationsPerformanceTest extends PerformanceTestCase
{
    protected bool $enableQueryLog = true;

    private Organization $organization;

    private User $user;

    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create();
        // Use TestCase helper to properly create user with role
        $this->user = $this->createUser([
            'organization_id' => $this->organization->id,
            'password' => Hash::make('password123'),
        ], 'Super Admin');

        Passport::actingAs($this->user);
        $this->accessToken = $this->user->createToken('Test Token')->accessToken;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_user_import_100_records_meets_target(): void
    {
        $csv = $this->generateCsvFile(100);

        $metrics = $this->measure(function () use ($csv) {
            return $this->postJson('/api/v1/bulk/users/import', [
                'file' => $csv,
                'organization_id' => $this->organization->id,
            ], [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);
        }, 'bulk_import_100');

        $this->metrics['bulk_import_100_result']['response']->assertStatus(200);

        $this->assertResponseTime($metrics['duration_ms'], 2000, 'Importing 100 users should take < 2 seconds');
        $this->assertMemoryUsage($metrics['memory_used_mb'], 50, 'Memory usage should be < 50MB');

        $this->recordBaseline('bulk_import_100', $metrics);

        echo "\n✓ Bulk Import (100 records) Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
        echo '  Memory: '.number_format($metrics['memory_used_mb'], 2)." MB\n";
        echo '  Queries: '.$metrics['query_count']."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_user_import_1000_records_meets_target(): void
    {
        $csv = $this->generateCsvFile(1000);

        $metrics = $this->measure(function () use ($csv) {
            return $this->postJson('/api/v1/bulk/users/import', [
                'file' => $csv,
                'organization_id' => $this->organization->id,
            ], [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);
        }, 'bulk_import_1000');

        $this->metrics['bulk_import_1000_result']['response']->assertStatus(200);

        $this->assertResponseTime($metrics['duration_ms'], 5000, 'Importing 1000 users should take < 5 seconds');
        $this->assertMemoryUsage($metrics['memory_used_mb'], 100, 'Memory usage should be < 100MB');

        $this->recordBaseline('bulk_import_1000', $metrics);

        echo "\n✓ Bulk Import (1,000 records) Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
        echo '  Memory: '.number_format($metrics['memory_used_mb'], 2)." MB\n";
        echo '  Rate: '.number_format(1000 / ($metrics['duration_ms'] / 1000), 2)." records/sec\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_user_export_100_records_meets_target(): void
    {
        User::factory()->count(100)->for($this->organization)->create();

        $metrics = $this->measure(function () {
            return $this->getJson('/api/v1/bulk/users/export?format=csv', [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);
        }, 'bulk_export_100');

        $this->metrics['bulk_export_100_result']['response']->assertStatus(200);

        $this->assertResponseTime($metrics['duration_ms'], 1000, 'Exporting 100 users should take < 1 second');
        $this->assertMemoryUsage($metrics['memory_used_mb'], 30, 'Memory usage should be < 30MB');

        echo "\n✓ Bulk Export (100 records) Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
        echo '  Memory: '.number_format($metrics['memory_used_mb'], 2)." MB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_user_export_1000_records_meets_target(): void
    {
        User::factory()->count(1000)->for($this->organization)->create();

        $metrics = $this->measure(function () {
            return $this->getJson('/api/v1/bulk/users/export?format=csv', [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);
        }, 'bulk_export_1000');

        $this->metrics['bulk_export_1000_result']['response']->assertStatus(200);

        $this->assertResponseTime($metrics['duration_ms'], 3000, 'Exporting 1000 users should take < 3 seconds');
        $this->assertMemoryUsage($metrics['memory_used_mb'], 100, 'Memory usage should be < 100MB');

        $this->recordBaseline('bulk_export_1000', $metrics);

        echo "\n✓ Bulk Export (1,000 records) Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
        echo '  Memory: '.number_format($metrics['memory_used_mb'], 2)." MB\n";
        echo '  Rate: '.number_format(1000 / ($metrics['duration_ms'] / 1000), 2)." records/sec\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_user_update_meets_target(): void
    {
        $users = User::factory()->count(50)->for($this->organization)->create();

        $updateData = $users->map(fn ($user) => [
            'id' => $user->id,
            'is_active' => false,
        ])->toArray();

        $metrics = $this->measure(function () use ($updateData) {
            return $this->patchJson('/api/v1/bulk/users/update', [
                'users' => $updateData,
            ], [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);
        }, 'bulk_update_50');

        $this->metrics['bulk_update_50_result']['response']->assertStatus(200);

        $this->assertResponseTime($metrics['duration_ms'], 1500, 'Bulk updating 50 users should take < 1.5 seconds');

        echo "\n✓ Bulk Update (50 records) Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
        echo '  Query Count: '.$metrics['query_count']."\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function bulk_user_delete_meets_target(): void
    {
        $users = User::factory()->count(30)->for($this->organization)->create();
        $userIds = $users->pluck('id')->toArray();

        $metrics = $this->measure(function () use ($userIds) {
            return $this->deleteJson('/api/v1/bulk/users/delete', [
                'user_ids' => $userIds,
            ], [
                'Authorization' => "Bearer {$this->accessToken}",
            ]);
        }, 'bulk_delete_30');

        $this->metrics['bulk_delete_30_result']['response']->assertStatus(200);

        $this->assertResponseTime($metrics['duration_ms'], 1000, 'Bulk deleting 30 users should take < 1 second');

        echo "\n✓ Bulk Delete (30 records) Performance:\n";
        echo '  Duration: '.number_format($metrics['duration_ms'], 2)." ms\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function pagination_with_large_dataset_meets_target(): void
    {
        User::factory()->count(1000)->for($this->organization)->create();

        $samples = [];

        // Test first page
        for ($i = 0; $i < 5; $i++) {
            $metrics = $this->measure(function () {
                return $this->getJson('/api/v1/users?page=1&per_page=50', [
                    'Authorization' => "Bearer {$this->accessToken}",
                ]);
            }, "pagination_first_{$i}");

            $samples[] = $metrics['duration_ms'];
        }

        $avgFirstPage = array_sum($samples) / count($samples);

        // Test middle page
        $samples = [];
        for ($i = 0; $i < 5; $i++) {
            $metrics = $this->measure(function () {
                return $this->getJson('/api/v1/users?page=10&per_page=50', [
                    'Authorization' => "Bearer {$this->accessToken}",
                ]);
            }, "pagination_middle_{$i}");

            $samples[] = $metrics['duration_ms'];
        }

        $avgMiddlePage = array_sum($samples) / count($samples);

        $this->assertResponseTime($avgFirstPage, 200, 'First page should load in < 200ms');
        $this->assertResponseTime($avgMiddlePage, 250, 'Middle page should load in < 250ms');

        echo "\n✓ Pagination Performance (1,000 total records):\n";
        echo '  First Page (avg): '.number_format($avgFirstPage, 2)." ms\n";
        echo '  Middle Page (avg): '.number_format($avgMiddlePage, 2)." ms\n";
    }

    /**
     * Generate CSV file for testing
     */
    private function generateCsvFile(int $rows): UploadedFile
    {
        $csvData = "name,email,password\n";

        for ($i = 1; $i <= $rows; $i++) {
            $csvData .= "Test User {$i},test{$i}@example.com,password123\n";
        }

        $filename = "test_users_{$rows}.csv";
        Storage::put($filename, $csvData);

        return new UploadedFile(
            Storage::path($filename),
            $filename,
            'text/csv',
            null,
            true
        );
    }
}
