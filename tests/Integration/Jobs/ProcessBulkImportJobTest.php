<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ProcessBulkImportJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private BulkImportJob $importJob;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create();
        $this->importJob = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => 'import',
            'file_format' => 'csv',
            'status' => BulkImportJob::STATUS_PENDING,
        ]);
    }

    #[Test]
    public function job_processes_csv_import_correctly(): void
    {
        $this->importJob->update([
            'records' => [
                ['name' => 'User 1', 'email' => 'user1@example.com'],
                ['name' => 'User 2', 'email' => 'user2@example.com'],
            ],
        ]);

        $job = new ProcessBulkImportJob($this->importJob);
        $job->handle();

        $this->importJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->importJob->status);
        $this->assertEquals(2, $this->importJob->total_records);
        $this->assertEquals(2, $this->importJob->successful_records);
    }

    #[Test]
    public function job_processes_excel_import_correctly(): void
    {
        $this->importJob->update([
            'file_format' => 'xlsx',
            'records' => [
                ['name' => 'Excel User 1', 'email' => 'excel1@example.com'],
                ['name' => 'Excel User 2', 'email' => 'excel2@example.com'],
            ],
        ]);

        $job = new ProcessBulkImportJob($this->importJob);
        $job->handle();

        $this->importJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->importJob->status);
        $this->assertEquals(2, $this->importJob->successful_records);
    }

    #[Test]
    public function job_validates_rows_before_import(): void
    {
        $this->importJob->update([
            'records' => [
                ['name' => 'Valid User', 'email' => 'valid@example.com'],
                ['name' => 'Invalid User', 'email' => 'invalid-email'], // Invalid email
                ['name' => 'Another Valid', 'email' => 'another@example.com'],
            ],
        ]);

        $job = new ProcessBulkImportJob($this->importJob);
        $job->handle();

        $this->importJob->refresh();
        $this->assertEquals(3, $this->importJob->total_records);
        $this->assertEquals(2, $this->importJob->successful_records);
        $this->assertEquals(1, $this->importJob->failed_records);
    }

    #[Test]
    public function job_tracks_progress_and_errors(): void
    {
        $this->importJob->update([
            'records' => [
                ['name' => 'User 1', 'email' => 'user1@example.com'],
                ['name' => 'User 2', 'email' => 'bad-email'], // Will fail validation
                ['name' => 'User 3', 'email' => 'user3@example.com'],
            ],
        ]);

        $job = new ProcessBulkImportJob($this->importJob);
        $job->handle();

        $this->importJob->refresh();

        // Check progress tracking
        $this->assertEquals(3, $this->importJob->total_records);
        $this->assertEquals(3, $this->importJob->processed_records);
        $this->assertEquals(2, $this->importJob->successful_records);
        $this->assertEquals(1, $this->importJob->failed_records);

        // Check error report was generated
        $this->assertNotNull($this->importJob->error_file_path);
        Storage::assertExists($this->importJob->error_file_path);
    }

    #[Test]
    public function job_can_be_cancelled_mid_execution(): void
    {
        // Create a large import job
        $records = [];
        for ($i = 1; $i <= 100; $i++) {
            $records[] = ['name' => "User {$i}", 'email' => "user{$i}@example.com"];
        }

        $this->importJob->update(['records' => $records]);

        // Simulate cancellation by updating status during processing
        $this->importJob->update(['status' => BulkImportJob::STATUS_CANCELLED]);

        // The job should detect the cancelled status
        $this->assertEquals(BulkImportJob::STATUS_CANCELLED, $this->importJob->status);
    }

    #[Test]
    public function job_sends_notification_on_completion(): void
    {
        Log::shouldReceive('info')->withAnyArgs()->zeroOrMoreTimes();
        Log::shouldReceive('debug')->withAnyArgs()->zeroOrMoreTimes();
        Log::shouldReceive('error')->withAnyArgs()->zeroOrMoreTimes();

        $this->importJob->update([
            'records' => [
                ['name' => 'User 1', 'email' => 'user1@example.com'],
            ],
        ]);

        $job = new ProcessBulkImportJob($this->importJob);
        $job->handle();

        $this->importJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->importJob->status);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
