<?php

namespace Tests\Integration\BulkOperations;

use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Spatie\Permission\Models\Role;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Bulk User Import operations
 *
 * Tests the complete workflow of importing users from CSV, Excel, and JSON files
 * including validation, error handling, job management, and file processing.
 */
class BulkUserImportTest extends IntegrationTestCase
{
    private Organization $organization;

    private User $adminUser;

    private string $apiBase = '/api/v1/bulk';

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        Queue::fake();

        // Create organization and admin user
        $this->organization = Organization::factory()->create([
            'name' => 'Import Test Org',
        ]);

        // Ensure roles exist
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'admin@importtest.com',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_users_from_csv_successfully(): void
    {
        // ARRANGE: Create CSV file with valid user data
        $csvContent = "email,name,password\n"
            ."user1@example.com,User One,Password123!\n"
            ."user2@example.com,User Two,Password456!\n"
            ."user3@example.com,User Three,Password789!";

        $file = UploadedFile::fake()->createWithContent(
            'users.csv',
            $csvContent
        );

        // ACT: Upload CSV file for import
        $response = $this->actingAsApiUserWithToken($this->adminUser, ['users.manage'])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'csv',
                'update_existing' => false,
                'skip_invalid' => true,
                'send_invitations' => false,
                'auto_generate_passwords' => false,
                'default_role' => 'User',
                'batch_size' => 100,
            ]);

        // ASSERT: Response indicates successful job creation
        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'job_id',
                    'status',
                    'type',
                ],
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'status' => 'pending',
                    'type' => 'import',
                ],
            ]);

        // ASSERT: Job was created in database
        $this->assertDatabaseHas('bulk_import_jobs', [
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_PENDING,
            'file_format' => 'csv',
        ]);

        // ASSERT: File was stored
        $job = BulkImportJob::latest()->first();
        Storage::disk('local')->assertExists($job->file_path);

        // ASSERT: Job was dispatched to queue
        Queue::assertPushed(ProcessBulkImportJob::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_users_from_excel_successfully(): void
    {
        // ARRANGE: Create Excel file (simulated as CSV since UploadedFile::fake() creates text files)
        $file = UploadedFile::fake()->create('users.xlsx', 500, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

        // ACT: Upload Excel file for import
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'xlsx',
                'update_existing' => true,
                'skip_invalid' => false,
                'send_invitations' => true,
            ]);

        // ASSERT: Response indicates successful job creation
        $response->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => [
                    'status' => 'pending',
                    'type' => 'import',
                ],
            ]);

        // ASSERT: Job has correct format and options
        $this->assertDatabaseHas('bulk_import_jobs', [
            'type' => BulkImportJob::TYPE_IMPORT,
            'file_format' => 'xlsx',
        ]);

        $job = BulkImportJob::latest()->first();
        $this->assertTrue($job->options['update_existing']);
        $this->assertFalse($job->options['skip_invalid']);
        $this->assertTrue($job->options['send_invitations']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_users_from_json_successfully(): void
    {
        // ARRANGE: Create JSON file with valid user data
        $jsonContent = json_encode([
            ['email' => 'json1@example.com', 'name' => 'JSON User 1', 'password' => 'Pass123!'],
            ['email' => 'json2@example.com', 'name' => 'JSON User 2', 'password' => 'Pass456!'],
        ]);

        $file = UploadedFile::fake()->createWithContent(
            'users.json',
            $jsonContent
        );

        // ACT: Upload JSON file for import
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'json',
                'auto_generate_passwords' => true,
            ]);

        // ASSERT: Response indicates successful job creation
        $response->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => [
                    'status' => 'pending',
                    'type' => 'import',
                ],
            ]);

        // ASSERT: Job was created with JSON format
        $this->assertDatabaseHas('bulk_import_jobs', [
            'file_format' => 'json',
        ]);

        // ASSERT: Auto-generate passwords option is set
        $job = BulkImportJob::latest()->first();
        $this->assertTrue($job->options['auto_generate_passwords']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_validates_file_format(): void
    {
        // ARRANGE: Create file with invalid format
        $file = UploadedFile::fake()->create('users.pdf', 100);

        // ACT: Attempt to upload invalid file
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'pdf',
            ]);

        // ASSERT: Request is rejected
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['format']);

        // ASSERT: No job was created
        $this->assertDatabaseCount('bulk_import_jobs', 0);

        // ASSERT: No job was dispatched
        Queue::assertNotPushed(ProcessBulkImportJob::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_handles_duplicate_emails_with_update_existing(): void
    {
        // ARRANGE: Create existing user
        $existingUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'duplicate@example.com',
            'name' => 'Original Name',
        ]);

        // Create CSV with duplicate email
        $csvContent = "email,name,password\n"
            ."duplicate@example.com,Updated Name,NewPassword123!";

        $file = UploadedFile::fake()->createWithContent('users.csv', $csvContent);

        // ACT: Import with update_existing = true
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'csv',
                'update_existing' => true,
            ]);

        // ASSERT: Import job created successfully
        $response->assertStatus(201);

        // ASSERT: Job has update_existing flag enabled
        $job = BulkImportJob::latest()->first();
        $this->assertTrue($job->options['update_existing']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_handles_invalid_data_with_skip_invalid(): void
    {
        // ARRANGE: Create CSV with some invalid data
        $csvContent = "email,name,password\n"
            ."valid@example.com,Valid User,Password123!\n"
            ."invalid-email,Invalid User,Pass\n"  // Invalid email
            ."another@example.com,Another User,Password456!";

        $file = UploadedFile::fake()->createWithContent('users.csv', $csvContent);

        // ACT: Import with skip_invalid = true
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'csv',
                'skip_invalid' => true,
            ]);

        // ASSERT: Import job created
        $response->assertStatus(201);

        // ASSERT: Job has skip_invalid flag
        $job = BulkImportJob::latest()->first();
        $this->assertTrue($job->options['skip_invalid']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function track_import_job_status_and_progress(): void
    {
        // ARRANGE: Create an import job with progress data
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_PROCESSING,
            'total_records' => 100,
            'processed_records' => 45,
            'valid_records' => 40,
            'invalid_records' => 5,
            'failed_records' => 0,
            'file_format' => 'csv',
            'file_size' => 5120,
            'started_at' => now()->subMinutes(5),
        ]);

        // ACT: Get job status
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports/{$job->id}");

        // ASSERT: Response contains complete job status
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $job->id,
                    'type' => 'import',
                    'status' => 'processing',
                    'total_records' => 100,
                    'processed_records' => 45,
                    'valid_records' => 40,
                    'invalid_records' => 5,
                    'failed_records' => 0,
                    'progress_percentage' => 45,
                    'file_format' => 'csv',
                ],
            ])
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'type',
                    'status',
                    'status_label',
                    'total_records',
                    'processed_records',
                    'progress_percentage',
                    'file_format',
                    'file_size',
                    'has_errors',
                    'error_count',
                    'started_at',
                    'created_at',
                    'created_by' => ['id', 'name', 'email'],
                ],
            ]);

        // ASSERT: Progress percentage is calculated correctly
        $this->assertEquals(45, $response->json('data.progress_percentage'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function retry_failed_import_job(): void
    {
        // ARRANGE: Create a failed import job
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_FAILED,
            'file_path' => 'imports/test-file.csv',
            'file_format' => 'csv',
            'total_records' => 50,
            'processed_records' => 20,
            'failed_records' => 20,
            'errors' => [
                ['row' => 1, 'message' => 'Invalid email format'],
                ['row' => 5, 'message' => 'Duplicate email'],
            ],
        ]);

        // Ensure file exists in storage
        Storage::disk('local')->put($job->file_path, 'test content');

        // ACT: Retry the failed job
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/imports/{$job->id}/retry");

        // ASSERT: Response indicates successful retry
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'message' => 'Job restarted successfully',
                'data' => [
                    'job_id' => $job->id,
                    'status' => BulkImportJob::STATUS_PENDING,
                ],
            ]);

        // ASSERT: Job status was reset to pending
        $job->refresh();
        $this->assertEquals(BulkImportJob::STATUS_PENDING, $job->status);
        $this->assertEquals(0, $job->processed_records);
        $this->assertEquals(0, $job->failed_records);
        $this->assertNull($job->errors);
        $this->assertNull($job->started_at);
        $this->assertNull($job->completed_at);

        // ASSERT: Job was re-dispatched to queue
        Queue::assertPushed(ProcessBulkImportJob::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cancel_running_import_job(): void
    {
        // ARRANGE: Create a processing import job
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_PROCESSING,
            'file_format' => 'csv',
            'total_records' => 1000,
            'processed_records' => 250,
            'started_at' => now()->subMinutes(10),
        ]);

        // ACT: Cancel the running job
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/imports/{$job->id}/cancel");

        // ASSERT: Response indicates successful cancellation
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'message' => 'Job cancelled successfully',
            ]);

        // ASSERT: Job status was changed to cancelled
        $job->refresh();
        $this->assertEquals(BulkImportJob::STATUS_CANCELLED, $job->status);
        $this->assertNotNull($job->completed_at);
        $this->assertNotNull($job->processing_time);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cannot_cancel_completed_import_job(): void
    {
        // ARRANGE: Create a completed import job
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_COMPLETED,
            'file_format' => 'csv',
            'completed_at' => now(),
        ]);

        // ACT: Attempt to cancel completed job
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/imports/{$job->id}/cancel");

        // ASSERT: Request is rejected
        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'message' => 'Job cannot be cancelled (not in progress)',
            ]);

        // ASSERT: Job status unchanged
        $job->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $job->status);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function download_import_error_report(): void
    {
        // ARRANGE: Create a failed job with errors
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_COMPLETED_WITH_ERRORS,
            'file_format' => 'csv',
            'errors' => [
                [
                    'row' => 2,
                    'data' => ['email' => 'invalid', 'name' => 'Test User'],
                    'errors' => ['Email must be a valid email address'],
                ],
                [
                    'row' => 5,
                    'data' => ['email' => 'duplicate@example.com', 'name' => 'Duplicate'],
                    'errors' => ['Email already exists'],
                ],
            ],
            'error_file_path' => 'imports/errors_'.$this->adminUser->id.'.csv',
        ]);

        // Create error file in storage
        Storage::disk('local')->put($job->error_file_path, "row,email,name,errors\n2,invalid,Test User,Email validation failed");

        // ACT: Download error report
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports/{$job->id}/errors");

        // ASSERT: File download response
        $response->assertOk();
        $response->assertDownload();

        // ASSERT: Response has correct content type
        $this->assertStringContainsString('text/csv', $response->headers->get('content-type'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_validates_file_size_limit(): void
    {
        // ARRANGE: Create file exceeding size limit (10MB)
        $file = UploadedFile::fake()->create('large-users.csv', 15000); // 15MB

        // ACT: Attempt to upload oversized file
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/import", [
                'file' => $file,
                'format' => 'csv',
            ]);

        // ASSERT: Validation error for file size
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['file']);

        // ASSERT: No job was created
        $this->assertDatabaseCount('bulk_import_jobs', 0);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_requires_authentication(): void
    {
        // ARRANGE: Create valid CSV file
        $file = UploadedFile::fake()->create('users.csv', 100);

        // ACT: Attempt import without authentication
        $response = $this->postJson("{$this->apiBase}/users/import", [
            'file' => $file,
            'format' => 'csv',
        ]);

        // ASSERT: Unauthorized response
        $response->assertUnauthorized();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function import_enforces_organization_boundary(): void
    {
        // ARRANGE: Create job for another organization
        $otherOrganization = Organization::factory()->create();
        $otherUser = $this->createApiOrganizationAdmin([
            'organization_id' => $otherOrganization->id,
        ]);

        $otherJob = BulkImportJob::factory()->create([
            'organization_id' => $otherOrganization->id,
            'created_by' => $otherUser->id,
            'type' => BulkImportJob::TYPE_IMPORT,
        ]);

        // ACT: Attempt to access another organization's job
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports/{$otherJob->id}");

        // ASSERT: Access denied
        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function list_import_jobs_with_filters(): void
    {
        // ARRANGE: Create multiple import jobs
        BulkImportJob::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'type' => BulkImportJob::TYPE_IMPORT,
            'status' => BulkImportJob::STATUS_COMPLETED,
            'created_at' => now()->subDays(5),
        ]);

        BulkImportJob::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
            'type' => BulkImportJob::TYPE_IMPORT,
            'status' => BulkImportJob::STATUS_FAILED,
            'created_at' => now()->subDays(2),
        ]);

        BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => BulkImportJob::TYPE_IMPORT,
            'status' => BulkImportJob::STATUS_PROCESSING,
            'created_at' => now(),
        ]);

        // ACT: List all import jobs
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports");

        // ASSERT: Returns all organization's jobs
        $response->assertOk()
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'type',
                        'status',
                        'created_at',
                    ],
                ],
                'pagination' => [
                    'current_page',
                    'per_page',
                    'total',
                    'last_page',
                ],
            ]);

        $this->assertEquals(6, $response->json('pagination.total'));

        // ACT: Filter by status
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports?status=failed");

        // ASSERT: Returns only failed jobs
        $this->assertEquals(2, count($response->json('data')));

        // ACT: Filter by type
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports?type=import");

        // ASSERT: Returns only import jobs
        $response->assertOk();
        foreach ($response->json('data') as $job) {
            $this->assertEquals('import', $job['type']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function delete_completed_import_job(): void
    {
        // ARRANGE: Create completed job with file
        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'type' => BulkImportJob::TYPE_IMPORT,
            'status' => BulkImportJob::STATUS_COMPLETED,
            'file_path' => 'imports/test-delete.csv',
        ]);

        Storage::disk('local')->put($job->file_path, 'test data');

        // ACT: Delete the job
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->deleteJson("{$this->apiBase}/imports/{$job->id}");

        // ASSERT: Job deleted successfully
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'message' => 'Job deleted successfully',
            ]);

        // ASSERT: Job removed from database
        $this->assertDatabaseMissing('bulk_import_jobs', [
            'id' => $job->id,
        ]);

        // ASSERT: Associated file deleted
        Storage::disk('local')->assertMissing($job->file_path);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cannot_delete_processing_import_job(): void
    {
        // ARRANGE: Create processing job
        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'type' => BulkImportJob::TYPE_IMPORT,
            'status' => BulkImportJob::STATUS_PROCESSING,
        ]);

        // ACT: Attempt to delete processing job
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->deleteJson("{$this->apiBase}/imports/{$job->id}");

        // ASSERT: Request rejected
        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'message' => 'Cannot delete a job that is in progress',
            ]);

        // ASSERT: Job still exists
        $this->assertDatabaseHas('bulk_import_jobs', [
            'id' => $job->id,
            'status' => BulkImportJob::STATUS_PROCESSING,
        ]);
    }
}
