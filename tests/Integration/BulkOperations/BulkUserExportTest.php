<?php

namespace Tests\Integration\BulkOperations;

use App\Jobs\ExportUsersJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Spatie\Permission\Models\Role;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Bulk User Export operations
 *
 * Tests the complete workflow of exporting users to CSV, Excel, and JSON files
 * including filtering, job management, and download functionality.
 */
class BulkUserExportTest extends IntegrationTestCase
{
    private Organization $organization;

    private User $adminUser;

    private string $apiBase = '/api/v1/bulk';

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        Queue::fake();

        // Create organization and roles
        $this->organization = Organization::factory()->create([
            'name' => 'Export Test Org',
        ]);

        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Manager', 'guard_name' => 'api']);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'admin@exporttest.com',
        ]);

        // Create test users for export
        User::factory()->count(10)->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
            'email_verified_at' => now(),
        ]);

        User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
            'is_active' => false,
            'email_verified_at' => null,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_to_csv_successfully(): void
    {
        // ACT: Request CSV export
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
            ]);

        // ASSERT: Response indicates successful export job creation
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
                    'type' => 'export',
                ],
            ]);

        // ASSERT: Export job was created in database
        $this->assertDatabaseHas('bulk_import_jobs', [
            'type' => BulkImportJob::TYPE_EXPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_PENDING,
            'file_format' => 'csv',
        ]);

        // ASSERT: Export job was dispatched to queue
        $job = BulkImportJob::latest()->first();
        Queue::assertPushed(ExportUsersJob::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_to_json_successfully(): void
    {
        // ACT: Request JSON export
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'json',
                'fields' => ['id', 'email', 'name', 'created_at'],
            ]);

        // ASSERT: Export job created with JSON format
        $response->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => [
                    'status' => 'pending',
                    'type' => 'export',
                ],
            ]);

        // ASSERT: Job has correct format in database
        $this->assertDatabaseHas('bulk_import_jobs', [
            'type' => BulkImportJob::TYPE_EXPORT,
            'file_format' => 'json',
        ]);

        // ASSERT: Job has field filters
        $job = BulkImportJob::latest()->first();
        $this->assertEquals(['id', 'email', 'name', 'created_at'], $job->options['fields']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_to_excel_successfully(): void
    {
        // ACT: Request Excel export
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'xlsx',
                'fields' => ['email', 'name', 'organization_name', 'roles'],
            ]);

        // ASSERT: Export job created with Excel format
        $response->assertStatus(201)
            ->assertJson([
                'success' => true,
                'data' => [
                    'status' => 'pending',
                    'type' => 'export',
                ],
            ]);

        // ASSERT: Job has Excel format
        $this->assertDatabaseHas('bulk_import_jobs', [
            'type' => BulkImportJob::TYPE_EXPORT,
            'file_format' => 'xlsx',
        ]);

        // ASSERT: Job dispatched to queue
        Queue::assertPushed(ExportUsersJob::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_filtered_by_date_range(): void
    {
        // ARRANGE: Create users in specific date range
        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'created_at' => now()->subDays(15),
        ]);

        User::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
            'created_at' => now()->subDays(45),
        ]);

        // ACT: Export with date range filter
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'date_from' => now()->subDays(30)->format('Y-m-d'),
                'date_to' => now()->format('Y-m-d'),
            ]);

        // ASSERT: Export job created
        $response->assertStatus(201);

        // ASSERT: Job has date filters in options
        $job = BulkImportJob::latest()->first();
        $this->assertNotNull($job->options['date_from']);
        $this->assertNotNull($job->options['date_to']);
        $this->assertEquals(
            now()->subDays(30)->format('Y-m-d'),
            $job->options['date_from']
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_filtered_by_organization(): void
    {
        // ARRANGE: Create another organization with users
        $otherOrganization = Organization::factory()->create();
        User::factory()->count(5)->create([
            'organization_id' => $otherOrganization->id,
        ]);

        // ACT: Export users (should only include current organization)
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'json',
            ]);

        // ASSERT: Export job created
        $response->assertStatus(201);

        // ASSERT: Job is scoped to admin's organization
        $job = BulkImportJob::latest()->first();
        $this->assertEquals($this->organization->id, $job->organization_id);
        $this->assertEquals($this->organization->id, $job->options['organization_id']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_with_role_filter(): void
    {
        // ARRANGE: Assign roles to some users
        $managerRole = Role::findByName('Manager', 'api');
        $users = User::where('organization_id', $this->organization->id)
            ->limit(3)
            ->get();

        foreach ($users as $user) {
            $user->assignRole($managerRole);
        }

        // ACT: Export users with specific role
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'roles' => ['Manager'],
            ]);

        // ASSERT: Export job created with role filter
        $response->assertStatus(201);

        $job = BulkImportJob::latest()->first();
        $this->assertEquals(['Manager'], $job->options['roles']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_with_active_only_filter(): void
    {
        // ACT: Export only active users
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'json',
                'active_only' => true,
            ]);

        // ASSERT: Export job created with active filter
        $response->assertStatus(201);

        $job = BulkImportJob::latest()->first();
        $this->assertTrue($job->options['active_only']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_with_email_verified_only_filter(): void
    {
        // ACT: Export only verified users
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'email_verified_only' => true,
            ]);

        // ASSERT: Export job created with verification filter
        $response->assertStatus(201);

        $job = BulkImportJob::latest()->first();
        $this->assertTrue($job->options['email_verified_only']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_users_with_limit(): void
    {
        // ACT: Export with record limit
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'limit' => 100,
            ]);

        // ASSERT: Export job created with limit
        $response->assertStatus(201);

        $job = BulkImportJob::latest()->first();
        $this->assertEquals(100, $job->options['limit']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function track_export_job_status(): void
    {
        // ARRANGE: Create an export job with progress
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_EXPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_PROCESSING,
            'file_format' => 'csv',
            'total_records' => 250,
            'processed_records' => 100,
            'started_at' => now()->subMinutes(2),
        ]);

        // ACT: Get export job status
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports/{$job->id}");

        // ASSERT: Response contains job status and progress
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $job->id,
                    'type' => 'export',
                    'status' => 'processing',
                    'total_records' => 250,
                    'processed_records' => 100,
                    'progress_percentage' => 40,
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
                    'started_at',
                    'created_by',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function download_completed_export_file(): void
    {
        // ARRANGE: Create completed export job with file
        $exportData = "email,name,created_at\n"
            ."user1@example.com,User One,2024-01-01\n"
            ."user2@example.com,User Two,2024-01-02";

        $filePath = 'exports/users_export_'.time().'.csv';
        Storage::disk('local')->put($filePath, $exportData);

        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_EXPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_COMPLETED,
            'file_format' => 'csv',
            'file_path' => $filePath,
            'total_records' => 2,
            'processed_records' => 2,
            'completed_at' => now(),
        ]);

        // ACT: Download export file
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/exports/{$job->id}/download");

        // ASSERT: File download response
        $response->assertOk();
        $response->assertDownload();

        // ASSERT: Response has correct content type for CSV
        $this->assertStringContainsString('text/csv', $response->headers->get('content-type'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cannot_download_incomplete_export(): void
    {
        // ARRANGE: Create pending export job
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_EXPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_PROCESSING,
            'file_format' => 'csv',
        ]);

        // ACT: Attempt to download incomplete export
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/exports/{$job->id}/download");

        // ASSERT: Request rejected
        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'message' => 'Export is not completed yet',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cannot_download_import_job_as_export(): void
    {
        // ARRANGE: Create import job (not export)
        $job = BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'status' => BulkImportJob::STATUS_COMPLETED,
        ]);

        // ACT: Attempt to download import job via export endpoint
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/exports/{$job->id}/download");

        // ASSERT: Request rejected
        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'message' => 'This is not an export job',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_validates_required_format(): void
    {
        // ACT: Attempt export without format
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                // Missing format field
            ]);

        // ASSERT: Validation error
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['format']);

        // ASSERT: No job was created
        $this->assertDatabaseCount('bulk_import_jobs', 0);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_validates_invalid_format(): void
    {
        // ACT: Attempt export with invalid format
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'pdf',
            ]);

        // ASSERT: Validation error
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['format']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_validates_date_range(): void
    {
        // ACT: Attempt export with invalid date range (end before start)
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'date_from' => now()->format('Y-m-d'),
                'date_to' => now()->subDays(10)->format('Y-m-d'),
            ]);

        // ASSERT: Validation error
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['date_to']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_validates_limit_maximum(): void
    {
        // ACT: Attempt export with limit exceeding maximum
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'limit' => 50000, // Exceeds 10,000 max
            ]);

        // ASSERT: Validation error
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['limit']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_requires_authentication(): void
    {
        // ACT: Attempt export without authentication
        $response = $this->postJson("{$this->apiBase}/users/export", [
            'format' => 'csv',
        ]);

        // ASSERT: Unauthorized response
        $response->assertUnauthorized();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_enforces_organization_boundary(): void
    {
        // ARRANGE: Create export job for another organization
        $otherOrganization = Organization::factory()->create();
        $otherUser = $this->createApiOrganizationAdmin([
            'organization_id' => $otherOrganization->id,
        ]);

        $otherJob = BulkImportJob::factory()->create([
            'organization_id' => $otherOrganization->id,
            'created_by' => $otherUser->id,
            'type' => BulkImportJob::TYPE_EXPORT,
            'status' => BulkImportJob::STATUS_COMPLETED,
            'file_path' => 'exports/other-org.csv',
        ]);

        Storage::disk('local')->put($otherJob->file_path, 'private data');

        // ACT: Attempt to download another organization's export
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/exports/{$otherJob->id}/download");

        // ASSERT: Access denied
        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function list_export_jobs_separate_from_imports(): void
    {
        // ARRANGE: Create both import and export jobs
        BulkImportJob::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'type' => BulkImportJob::TYPE_IMPORT,
        ]);

        BulkImportJob::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
            'type' => BulkImportJob::TYPE_EXPORT,
        ]);

        // ACT: List only export jobs
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->getJson("{$this->apiBase}/imports?type=export");

        // ASSERT: Returns only export jobs
        $response->assertOk();
        $data = $response->json('data');
        $this->assertCount(2, $data);

        foreach ($data as $job) {
            $this->assertEquals('export', $job['type']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_with_custom_field_selection(): void
    {
        // ACT: Export with specific fields
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'json',
                'fields' => ['email', 'name', 'is_active', 'mfa_enabled'],
            ]);

        // ASSERT: Export job created
        $response->assertStatus(201);

        // ASSERT: Job has field selection
        $job = BulkImportJob::latest()->first();
        $this->assertEquals(
            ['email', 'name', 'is_active', 'mfa_enabled'],
            $job->options['fields']
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function export_validates_invalid_field_names(): void
    {
        // ACT: Attempt export with invalid field
        $response = $this->actingAsApiUserWithToken($this->adminUser, ["users.manage"])
            ->postJson("{$this->apiBase}/users/export", [
                'format' => 'csv',
                'fields' => ['email', 'invalid_field', 'secret_data'],
            ]);

        // ASSERT: Validation error for invalid fields
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['fields.1', 'fields.2']);
    }
}
