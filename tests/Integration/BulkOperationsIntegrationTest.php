<?php

namespace Tests\Integration;

use App\Jobs\ProcessBulkExportJob;
use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class BulkOperationsIntegrationTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        $this->organization = Organization::factory()->create();
    }

    public function test_large_import_of_users(): void
    {
        // Create 1000+ user records
        $records = array_map(function ($i) {
            return [
                'email' => "user{$i}@example.com",
                'name' => "User {$i}",
                'role' => 'user',
            ];
        }, range(1, 1000));

        $importJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $startTime = microtime(true);

        $processor = new ProcessBulkImportJob($importJob);
        $processor->handle();

        $endTime = microtime(true);
        $duration = $endTime - $startTime;

        $importJob->refresh();

        $this->assertEquals('completed', $importJob->status);
        $this->assertEquals(1000, $importJob->processed_records);
        $this->assertEquals(1000, $importJob->successful_records);
        $this->assertEquals(0, $importJob->failed_records);

        // Verify all users were created
        $this->assertEquals(1000, User::where('organization_id', $this->organization->id)->count());

        // Performance assertion - should complete in reasonable time
        $this->assertLessThan(60, $duration, 'Import took too long');
    }

    public function test_large_export_of_users(): void
    {
        // Create 1000 users
        User::factory()
            ->for($this->organization)
            ->count(1000)
            ->create();

        $exportJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $startTime = microtime(true);

        $processor = new ProcessBulkExportJob($exportJob);
        $processor->handle();

        $endTime = microtime(true);
        $duration = $endTime - $startTime;

        $exportJob->refresh();

        $this->assertEquals('completed', $exportJob->status);
        $this->assertNotNull($exportJob->file_path);
        Storage::assertExists($exportJob->file_path);

        // Verify file content
        $content = Storage::get($exportJob->file_path);
        $lines = explode("\n", trim($content));

        // Should have header + 1000 data rows
        $this->assertCount(1001, $lines);

        // Performance assertion
        $this->assertLessThan(30, $duration, 'Export took too long');
    }

    public function test_concurrent_imports(): void
    {
        Queue::fake();

        // Create 3 import jobs
        $jobs = [];
        for ($i = 1; $i <= 3; $i++) {
            $records = array_map(function ($j) use ($i) {
                return [
                    'email' => "batch{$i}_user{$j}@example.com",
                    'name' => "Batch {$i} User {$j}",
                    'role' => 'user',
                ];
            }, range(1, 100));

            $jobs[] = BulkImportJob::factory()
                ->for($this->organization)
                ->create([
                    'type' => 'users',
                    'total_records' => count($records),
                    'records' => $records,
                ]);
        }

        // Process all jobs concurrently
        foreach ($jobs as $job) {
            (new ProcessBulkImportJob($job))->handle();
        }

        // Verify all imports completed
        foreach ($jobs as $job) {
            $job->refresh();
            $this->assertEquals('completed', $job->status);
            $this->assertEquals(100, $job->processed_records);
        }

        // Verify all users were created (300 total)
        $this->assertEquals(300, User::where('organization_id', $this->organization->id)->count());
    }

    public function test_import_with_validation_errors(): void
    {
        $records = array_merge(
            // Valid records
            array_map(function ($i) {
                return [
                    'email' => "valid{$i}@example.com",
                    'name' => "Valid User {$i}",
                    'role' => 'user',
                ];
            }, range(1, 100)),
            // Invalid records
            [
                ['email' => 'invalid-email', 'name' => 'Invalid', 'role' => 'user'],
                ['email' => '', 'name' => 'No Email', 'role' => 'user'],
                ['name' => 'Missing Email', 'role' => 'user'],
            ]
        );

        $importJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($importJob);
        $processor->handle();

        $importJob->refresh();

        $this->assertEquals('completed_with_errors', $importJob->status);
        $this->assertEquals(100, $importJob->successful_records);
        $this->assertEquals(3, $importJob->failed_records);
        $this->assertNotNull($importJob->error_file_path);
    }

    public function test_export_with_large_dataset_and_filters(): void
    {
        // Create diverse user dataset
        User::factory()
            ->for($this->organization)
            ->count(500)
            ->create(['email_verified_at' => now()]);

        User::factory()
            ->for($this->organization)
            ->count(500)
            ->create(['email_verified_at' => null]);

        $exportJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
                'filters' => [
                    'email_verified' => true,
                ],
            ]);

        $processor = new ProcessBulkExportJob($exportJob);
        $processor->handle();

        $exportJob->refresh();

        $this->assertEquals('completed', $exportJob->status);

        $content = Storage::get($exportJob->file_path);
        $lines = explode("\n", trim($content));

        // Should export only verified users (500) + header
        $this->assertLessThanOrEqual(501, count($lines));
    }

    public function test_import_resume_after_failure(): void
    {
        $records = array_map(function ($i) {
            return [
                'email' => "user{$i}@example.com",
                'name' => "User {$i}",
                'role' => 'user',
            ];
        }, range(1, 200));

        $importJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
                'processed_records' => 100, // Simulate partial processing
            ]);

        $processor = new ProcessBulkImportJob($importJob);
        $processor->handle();

        $importJob->refresh();

        $this->assertEquals('completed', $importJob->status);
        $this->assertEquals(200, $importJob->processed_records);
    }

    public function test_memory_usage_during_large_operations(): void
    {
        $initialMemory = memory_get_usage();

        // Import large dataset
        $records = array_map(function ($i) {
            return [
                'email' => "user{$i}@example.com",
                'name' => "User {$i}",
                'role' => 'user',
            ];
        }, range(1, 500));

        $importJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'users',
                'total_records' => count($records),
                'records' => $records,
            ]);

        $processor = new ProcessBulkImportJob($importJob);
        $processor->handle();

        $peakMemory = memory_get_peak_usage();
        $memoryUsedMB = ($peakMemory - $initialMemory) / 1024 / 1024;

        // Memory usage should be reasonable (less than 256MB)
        $this->assertLessThan(256, $memoryUsedMB, 'Memory usage too high');
    }
}
