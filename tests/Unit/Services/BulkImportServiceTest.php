<?php

namespace Tests\Unit\Services;

use App\Jobs\ExportUsersJob;
use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use App\Services\BulkImport\BulkImportService;
use App\Services\BulkImport\DTOs\ExportOptions;
use App\Services\BulkImport\DTOs\ImportOptions;
use App\Services\BulkImport\Parsers\CsvParser;
use App\Services\BulkImport\Parsers\ExcelParser;
use App\Services\BulkImport\Parsers\JsonParser;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class BulkImportServiceTest extends TestCase
{
    private BulkImportService $service;

    private Organization $organization;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new BulkImportService;
        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create(['organization_id' => $this->organization->id]);
        Storage::fake('local');
        Queue::fake();
    }

    public function test_import_creates_job_and_dispatches_queue(): void
    {
        $csv = "email,name\nuser1@example.com,User One\nuser2@example.com,User Two";
        $file = UploadedFile::fake()->createWithContent('users.csv', $csv);

        $options = new ImportOptions(
            format: 'csv',
            organizationId: $this->organization->id,
            updateExisting: false,
            skipInvalid: true
        );

        $job = $this->service->import($file, $options, $this->user->id);

        $this->assertInstanceOf(BulkImportJob::class, $job);
        $this->assertEquals(BulkImportJob::TYPE_IMPORT, $job->type);
        $this->assertEquals($this->organization->id, $job->organization_id);
        $this->assertEquals($this->user->id, $job->created_by);
        $this->assertEquals(BulkImportJob::STATUS_PENDING, $job->status);
        $this->assertEquals('csv', $job->file_format);
        $this->assertNotNull($job->file_path);

        Queue::assertPushed(ProcessBulkImportJob::class);
    }

    public function test_import_stores_file(): void
    {
        $csv = "email,name\nuser@example.com,User";
        $file = UploadedFile::fake()->createWithContent('users.csv', $csv);

        $options = new ImportOptions(
            format: 'csv',
            organizationId: $this->organization->id
        );

        $job = $this->service->import($file, $options, $this->user->id);

        Storage::disk('local')->assertExists($job->file_path);
    }

    public function test_import_validates_file_size(): void
    {
        $largeFile = UploadedFile::fake()->create('users.csv', 15000); // 15MB

        $options = new ImportOptions(
            format: 'csv',
            organizationId: $this->organization->id
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('File size exceeds maximum allowed');

        $this->service->import($largeFile, $options, $this->user->id);
    }

    public function test_import_validates_file_extension(): void
    {
        $file = UploadedFile::fake()->create('users.txt', 10);

        $options = new ImportOptions(
            format: 'csv',
            organizationId: $this->organization->id
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid file type');

        $this->service->import($file, $options, $this->user->id);
    }

    public function test_import_validates_mime_type(): void
    {
        // Create file with wrong mime type
        $file = UploadedFile::fake()->create('users.csv', 10, 'application/pdf');

        $options = new ImportOptions(
            format: 'csv',
            organizationId: $this->organization->id
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid file MIME type');

        $this->service->import($file, $options, $this->user->id);
    }

    public function test_export_creates_job_and_dispatches_queue(): void
    {
        $options = new ExportOptions(
            format: 'csv',
            organizationId: $this->organization->id
        );

        $job = $this->service->export($options, $this->user->id);

        $this->assertInstanceOf(BulkImportJob::class, $job);
        $this->assertEquals(BulkImportJob::TYPE_EXPORT, $job->type);
        $this->assertEquals($this->organization->id, $job->organization_id);
        $this->assertEquals($this->user->id, $job->created_by);
        $this->assertEquals(BulkImportJob::STATUS_PENDING, $job->status);
        $this->assertEquals('csv', $job->file_format);

        Queue::assertPushed(ExportUsersJob::class);
    }

    public function test_get_parser_returns_csv_parser(): void
    {
        $parser = $this->service->getParser('csv');

        $this->assertInstanceOf(CsvParser::class, $parser);
    }

    public function test_get_parser_returns_json_parser(): void
    {
        $parser = $this->service->getParser('json');

        $this->assertInstanceOf(JsonParser::class, $parser);
    }

    public function test_get_parser_returns_excel_parser_for_xlsx(): void
    {
        $parser = $this->service->getParser('xlsx');

        $this->assertInstanceOf(ExcelParser::class, $parser);
    }

    public function test_get_parser_returns_excel_parser_for_xls(): void
    {
        $parser = $this->service->getParser('xls');

        $this->assertInstanceOf(ExcelParser::class, $parser);
    }

    public function test_get_parser_case_insensitive(): void
    {
        $parser = $this->service->getParser('CSV');

        $this->assertInstanceOf(CsvParser::class, $parser);
    }

    public function test_get_parser_throws_exception_for_invalid_format(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported format: txt');

        $this->service->getParser('txt');
    }

    public function test_cancel_marks_job_as_cancelled(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_PROCESSING,
            ]);

        $result = $this->service->cancel($job);

        $this->assertTrue($result);
        $this->assertEquals(BulkImportJob::STATUS_CANCELLED, $job->fresh()->status);
    }

    public function test_cancel_returns_false_for_completed_job(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_COMPLETED,
            ]);

        $result = $this->service->cancel($job);

        $this->assertFalse($result);
    }

    public function test_cancel_marks_pending_job_as_cancelled(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_PENDING,
            ]);

        $result = $this->service->cancel($job);

        $this->assertTrue($result);
        $this->assertEquals(BulkImportJob::STATUS_CANCELLED, $job->fresh()->status);
    }

    public function test_retry_resets_failed_import_job(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => BulkImportJob::TYPE_IMPORT,
                'status' => BulkImportJob::STATUS_FAILED,
                'processed_records' => 50,
                'failed_records' => 10,
                'errors' => ['some' => 'errors'],
                'started_at' => now()->subHour(),
                'completed_at' => now(),
            ]);

        $retried = $this->service->retry($job);

        $this->assertEquals(BulkImportJob::STATUS_PENDING, $retried->status);
        $this->assertEquals(0, $retried->processed_records);
        $this->assertEquals(0, $retried->failed_records);
        $this->assertNull($retried->errors);
        $this->assertNull($retried->started_at);
        $this->assertNull($retried->completed_at);

        Queue::assertPushed(ProcessBulkImportJob::class);
    }

    public function test_retry_resets_failed_export_job(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => BulkImportJob::TYPE_EXPORT,
                'status' => BulkImportJob::STATUS_FAILED,
            ]);

        $this->service->retry($job);

        Queue::assertPushed(ExportUsersJob::class);
    }

    public function test_retry_throws_exception_for_non_failed_job(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_COMPLETED,
            ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Only failed jobs can be retried');

        $this->service->retry($job);
    }

    public function test_generate_error_report_creates_csv_file(): void
    {
        Storage::fake('local');

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'errors' => [
                    [
                        'row' => 1,
                        'data' => ['email' => 'invalid-email', 'name' => 'User One'],
                        'errors' => ['Invalid email format'],
                    ],
                    [
                        'row' => 2,
                        'data' => ['email' => 'user@example.com', 'name' => ''],
                        'errors' => ['Name is required'],
                    ],
                ],
            ]);

        $path = $this->service->generateErrorReport($job);

        $this->assertNotNull($path);
        $this->assertStringContainsString('errors_'.$job->id, $path);
        Storage::disk('local')->assertExists($path);

        // Verify the job was updated with error file path
        $this->assertEquals($path, $job->fresh()->error_file_path);
    }

    public function test_generate_error_report_returns_null_for_no_errors(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'errors' => null,
            ]);

        $path = $this->service->generateErrorReport($job);

        $this->assertNull($path);
    }

    public function test_generate_error_report_returns_null_for_empty_errors(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'errors' => [],
            ]);

        $path = $this->service->generateErrorReport($job);

        $this->assertNull($path);
    }

    public function test_cleanup_deletes_old_completed_jobs(): void
    {
        // Create old completed job
        $oldJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_COMPLETED,
                'created_at' => now()->subDays(40),
            ]);

        // Create recent job
        $recentJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_COMPLETED,
                'created_at' => now()->subDays(10),
            ]);

        $count = $this->service->cleanup(30);

        $this->assertEquals(1, $count);
        $this->assertModelMissing($oldJob);
        $this->assertModelExists($recentJob);
    }

    public function test_cleanup_deletes_old_failed_jobs(): void
    {
        $oldJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_FAILED,
                'created_at' => now()->subDays(40),
            ]);

        $count = $this->service->cleanup(30);

        $this->assertEquals(1, $count);
        $this->assertModelMissing($oldJob);
    }

    public function test_cleanup_does_not_delete_pending_jobs(): void
    {
        $oldJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_PENDING,
                'created_at' => now()->subDays(40),
            ]);

        $count = $this->service->cleanup(30);

        $this->assertEquals(0, $count);
        $this->assertModelExists($oldJob);
    }

    public function test_cleanup_does_not_delete_processing_jobs(): void
    {
        $oldJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_PROCESSING,
                'created_at' => now()->subDays(40),
            ]);

        $count = $this->service->cleanup(30);

        $this->assertEquals(0, $count);
        $this->assertModelExists($oldJob);
    }

    public function test_cleanup_respects_custom_days_parameter(): void
    {
        $job60Days = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_COMPLETED,
                'created_at' => now()->subDays(60),
            ]);

        $job40Days = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => BulkImportJob::STATUS_COMPLETED,
                'created_at' => now()->subDays(40),
            ]);

        $count = $this->service->cleanup(50);

        $this->assertEquals(1, $count);
        $this->assertModelMissing($job60Days);
        $this->assertModelExists($job40Days);
    }

    public function test_import_saves_import_options_correctly(): void
    {
        $csv = "email,name\nuser@example.com,User";
        $file = UploadedFile::fake()->createWithContent('users.csv', $csv);

        $options = new ImportOptions(
            format: 'csv',
            organizationId: $this->organization->id,
            updateExisting: true,
            skipInvalid: false,
            sendInvitations: true,
            autoGeneratePasswords: true,
            defaultRole: 'admin',
            batchSize: 50
        );

        $job = $this->service->import($file, $options, $this->user->id);

        $savedOptions = $job->options;
        $this->assertTrue($savedOptions['update_existing']);
        $this->assertFalse($savedOptions['skip_invalid']);
        $this->assertTrue($savedOptions['send_invitations']);
        $this->assertTrue($savedOptions['auto_generate_passwords']);
        $this->assertEquals('admin', $savedOptions['default_role']);
        $this->assertEquals(50, $savedOptions['batch_size']);
    }

    public function test_export_saves_export_options_correctly(): void
    {
        $options = new ExportOptions(
            format: 'json',
            organizationId: $this->organization->id,
            fields: ['email', 'name'],
            roles: ['admin'],
            dateFrom: '2024-01-01',
            dateTo: '2024-12-31',
            emailVerifiedOnly: true,
            activeOnly: true,
            limit: 1000
        );

        $job = $this->service->export($options, $this->user->id);

        $savedOptions = $job->options;
        $this->assertEquals(['email', 'name'], $savedOptions['fields']);
        $this->assertEquals(['admin'], $savedOptions['roles']);
        $this->assertEquals('2024-01-01', $savedOptions['date_from']);
        $this->assertEquals('2024-12-31', $savedOptions['date_to']);
        $this->assertTrue($savedOptions['email_verified_only']);
        $this->assertTrue($savedOptions['active_only']);
        $this->assertEquals(1000, $savedOptions['limit']);
    }
}
