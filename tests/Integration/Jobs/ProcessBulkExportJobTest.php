<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\ProcessBulkExportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ProcessBulkExportJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private BulkImportJob $exportJob;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create();
        $this->exportJob = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => 'export',
            'export_type' => 'users',
            'format' => 'csv',
            'status' => BulkImportJob::STATUS_PENDING,
        ]);
    }

    #[Test]
    public function job_exports_users_to_csv_with_filters(): void
    {
        // Create test users
        User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
            'email_verified_at' => now(),
        ]);

        $this->exportJob->update([
            'filters' => ['email_verified' => true],
        ]);

        $job = new ProcessBulkExportJob($this->exportJob);
        $job->handle();

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);
        $this->assertEquals(5, $this->exportJob->total_records);

        Storage::assertExists($this->exportJob->file_path);

        $content = Storage::get($this->exportJob->file_path);
        $this->assertStringContainsString('id,name,email', $content);
    }

    #[Test]
    public function job_exports_with_date_range_filtering(): void
    {
        // Create users with different dates
        User::factory()->create([
            'organization_id' => $this->organization->id,
            'created_at' => now()->subDays(10),
        ]);

        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'created_at' => now()->subDays(2),
        ]);

        $this->exportJob->update([
            'filters' => [
                'date_from' => now()->subDays(5)->format('Y-m-d'),
            ],
        ]);

        $job = new ProcessBulkExportJob($this->exportJob);
        $job->handle();

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);
        $this->assertEquals(3, $this->exportJob->total_records);
    }

    #[Test]
    public function job_exports_with_role_filtering(): void
    {
        // Create users with different roles
        $adminUser = $this->createUser(['organization_id' => $this->organization->id], 'Organization Admin');
        $regularUser = $this->createUser(['organization_id' => $this->organization->id], 'User');

        $this->exportJob->update([
            'filters' => ['roles' => ['Organization Admin']],
        ]);

        $job = new ProcessBulkExportJob($this->exportJob);
        $job->handle();

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);

        // Should export at least the admin user
        $this->assertGreaterThanOrEqual(1, $this->exportJob->total_records);
    }

    #[Test]
    public function job_handles_large_exports_with_chunking(): void
    {
        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Starting bulk export job/'), Mockery::any())
            ->once();

        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Completed bulk export job/'), Mockery::any())
            ->once();

        // Create a large number of users
        User::factory()->count(250)->create([
            'organization_id' => $this->organization->id,
        ]);

        $job = new ProcessBulkExportJob($this->exportJob);
        $job->handle();

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);
        $this->assertEquals(250, $this->exportJob->total_records);

        // Verify file exists and has content
        Storage::assertExists($this->exportJob->file_path);
        $this->assertGreaterThan(0, $this->exportJob->file_size);
    }

    #[Test]
    public function job_stores_file_in_storage(): void
    {
        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        $job = new ProcessBulkExportJob($this->exportJob);
        $job->handle();

        $this->exportJob->refresh();

        $this->assertNotNull($this->exportJob->file_path);
        $this->assertStringStartsWith('exports/', $this->exportJob->file_path);
        $this->assertStringContainsString('users_', $this->exportJob->file_path);
        $this->assertGreaterThan(0, $this->exportJob->file_size);

        Storage::assertExists($this->exportJob->file_path);
    }

    #[Test]
    public function job_provides_download_link(): void
    {
        User::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
        ]);

        $job = new ProcessBulkExportJob($this->exportJob);
        $job->handle();

        $this->exportJob->refresh();

        $this->assertNotNull($this->exportJob->file_path);

        // Verify the file can be accessed
        $this->assertTrue(Storage::exists($this->exportJob->file_path));

        // Verify download URL can be generated
        $url = Storage::url($this->exportJob->file_path);
        $this->assertNotEmpty($url);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
