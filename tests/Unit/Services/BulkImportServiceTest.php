<?php

namespace Tests\Unit\Services;

use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Services\BulkImportService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class BulkImportServiceTest extends TestCase
{
    private BulkImportService $service;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new BulkImportService;
        $this->organization = Organization::factory()->create();
        Storage::fake('local');
    }

    public function test_parses_csv_file(): void
    {
        $csv = "email,name,role\nuser1@example.com,User One,user\nuser2@example.com,User Two,admin";
        $file = UploadedFile::fake()->createWithContent('users.csv', $csv);

        $records = $this->service->parseCsvFile($file);

        $this->assertCount(2, $records);
        $this->assertEquals('user1@example.com', $records[0]['email']);
        $this->assertEquals('User One', $records[0]['name']);
    }

    public function test_parses_json_file(): void
    {
        $json = json_encode([
            ['email' => 'user1@example.com', 'name' => 'User One', 'role' => 'user'],
            ['email' => 'user2@example.com', 'name' => 'User Two', 'role' => 'admin'],
        ]);
        $file = UploadedFile::fake()->createWithContent('users.json', $json);

        $records = $this->service->parseJsonFile($file);

        $this->assertCount(2, $records);
        $this->assertEquals('user1@example.com', $records[0]['email']);
    }

    public function test_parses_excel_file(): void
    {
        // Create a simple XLSX file
        $file = UploadedFile::fake()->create('users.xlsx', 100, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

        // Mock the Excel parsing (in real implementation, use PhpSpreadsheet)
        $records = $this->service->parseExcelFile($file);

        $this->assertIsArray($records);
    }

    public function test_validates_records(): void
    {
        $records = [
            ['email' => 'valid@example.com', 'name' => 'Valid User'],
            ['email' => 'invalid-email', 'name' => 'Invalid User'],
            ['email' => 'another@example.com', 'name' => ''],
        ];

        $result = $this->service->validateRecords($records);

        $this->assertCount(1, $result['valid']);
        $this->assertCount(2, $result['invalid']);
    }

    public function test_creates_import_job(): void
    {
        $records = [
            ['email' => 'user1@example.com', 'name' => 'User One'],
            ['email' => 'user2@example.com', 'name' => 'User Two'],
        ];

        $job = $this->service->createImportJob($this->organization, 'users', $records);

        $this->assertInstanceOf(BulkImportJob::class, $job);
        $this->assertEquals($this->organization->id, $job->organization_id);
        $this->assertEquals('users', $job->type);
        $this->assertEquals('pending', $job->status);
        $this->assertEquals(2, $job->total_records);
    }

    public function test_handles_duplicate_emails(): void
    {
        $records = [
            ['email' => 'user@example.com', 'name' => 'User One'],
            ['email' => 'user@example.com', 'name' => 'User Two'],
        ];

        $result = $this->service->handleDuplicates($records, 'skip');

        $this->assertCount(1, $result['records']);
        $this->assertCount(1, $result['duplicates']);
    }

    public function test_handles_duplicate_emails_with_update_strategy(): void
    {
        $records = [
            ['email' => 'user@example.com', 'name' => 'User One'],
            ['email' => 'user@example.com', 'name' => 'User Updated'],
        ];

        $result = $this->service->handleDuplicates($records, 'update');

        $this->assertCount(1, $result['records']);
        $this->assertEquals('User Updated', $result['records'][0]['name']);
    }

    public function test_validates_required_fields(): void
    {
        $records = [
            ['email' => 'user@example.com', 'name' => 'User One'],
            ['name' => 'Missing Email'],
        ];

        $requiredFields = ['email', 'name'];
        $result = $this->service->validateRequiredFields($records, $requiredFields);

        $this->assertCount(1, $result['valid']);
        $this->assertCount(1, $result['invalid']);
    }

    public function test_normalizes_record_data(): void
    {
        $record = [
            'email' => '  USER@EXAMPLE.COM  ',
            'name' => '  John Doe  ',
            'role' => 'ADMIN',
        ];

        $normalized = $this->service->normalizeRecord($record);

        $this->assertEquals('user@example.com', $normalized['email']);
        $this->assertEquals('John Doe', $normalized['name']);
        $this->assertEquals('admin', $normalized['role']);
    }

    public function test_detects_csv_delimiter(): void
    {
        $csvComma = "email,name\nuser@example.com,User One";
        $csvSemicolon = "email;name\nuser@example.com;User One";

        $delimiterComma = $this->service->detectDelimiter($csvComma);
        $delimiterSemicolon = $this->service->detectDelimiter($csvSemicolon);

        $this->assertEquals(',', $delimiterComma);
        $this->assertEquals(';', $delimiterSemicolon);
    }

    public function test_validates_file_size(): void
    {
        $largeFile = UploadedFile::fake()->create('users.csv', 15000); // 15MB

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('File size exceeds maximum allowed');

        $this->service->validateFileSize($largeFile, 10000); // 10MB max
    }

    public function test_validates_file_type(): void
    {
        $invalidFile = UploadedFile::fake()->create('users.txt');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid file type');

        $this->service->validateFileType($invalidFile, ['csv', 'json', 'xlsx']);
    }

    public function test_calculates_import_progress(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'total_records' => 100,
                'processed_records' => 75,
            ]);

        $progress = $this->service->calculateProgress($job);

        $this->assertEquals(75, $progress);
    }

    public function test_generates_error_report(): void
    {
        $errors = [
            ['row' => 1, 'email' => 'invalid-email', 'error' => 'Invalid email format'],
            ['row' => 2, 'email' => 'user@example.com', 'error' => 'Missing required field: name'],
        ];

        $report = $this->service->generateErrorReport($errors);

        $this->assertStringContainsString('invalid-email', $report);
        $this->assertStringContainsString('Invalid email format', $report);
    }

    public function test_batch_processes_records(): void
    {
        $records = range(1, 250);
        $batchSize = 100;

        $batches = $this->service->batchRecords($records, $batchSize);

        $this->assertCount(3, $batches);
        $this->assertCount(100, $batches[0]);
        $this->assertCount(100, $batches[1]);
        $this->assertCount(50, $batches[2]);
    }

    public function test_validates_email_format(): void
    {
        $validEmail = 'user@example.com';
        $invalidEmail = 'invalid-email';

        $this->assertTrue($this->service->validateEmail($validEmail));
        $this->assertFalse($this->service->validateEmail($invalidEmail));
    }
}
