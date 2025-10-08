<?php

namespace Tests\Feature;

use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use App\Services\BulkImport\BulkImportService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Tests\TestCase;

class BulkImportExportTest extends TestCase
{
    protected Organization $organization;

    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        // Create organization and user
        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Setup default roles for organization
        $this->organization->setupDefaultRoles();

        // Assign admin role
        $this->user->setPermissionsTeamId($this->organization->id);
        $this->user->assignOrganizationRole('Organization Owner', $this->organization->id);

        Storage::fake('local');
        Storage::fake('public');
    }

    #[Test]
    public function it_can_create_import_job_via_api()
    {
        Passport::actingAs($this->user);

        $csvContent = "email,name,password\ntest@example.com,Test User,password123";
        $file = UploadedFile::fake()->createWithContent('users.csv', $csvContent);

        $response = $this->postJson('/api/v1/bulk/users/import', [
            'file' => $file,
            'format' => 'csv',
            'update_existing' => false,
            'skip_invalid' => true,
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => ['job_id', 'status', 'type'],
            ]);

        $this->assertDatabaseHas('bulk_import_jobs', [
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'type' => 'import',
            'status' => 'pending',
        ]);
    }

    #[Test]
    public function it_can_create_export_job_via_api()
    {
        Passport::actingAs($this->user);

        $response = $this->postJson('/api/v1/bulk/users/export', [
            'format' => 'csv',
            'fields' => ['id', 'email', 'name'],
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'message',
                'data' => ['job_id', 'status', 'type'],
            ]);

        $this->assertDatabaseHas('bulk_import_jobs', [
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'type' => 'export',
            'status' => 'pending',
        ]);
    }

    #[Test]
    public function it_can_list_import_export_jobs()
    {
        Passport::actingAs($this->user);

        // Create some jobs
        BulkImportJob::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
        ]);

        $response = $this->getJson('/api/v1/bulk/imports');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data',
                'pagination',
            ]);

        $this->assertCount(3, $response->json('data'));
    }

    #[Test]
    public function it_can_get_job_status()
    {
        Passport::actingAs($this->user);

        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'status' => 'completed',
            'total_records' => 10,
            'valid_records' => 8,
            'invalid_records' => 2,
        ]);

        $response = $this->getJson("/api/v1/bulk/imports/{$job->id}");

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $job->id,
                    'status' => 'completed',
                    'total_records' => 10,
                    'valid_records' => 8,
                    'invalid_records' => 2,
                ],
            ]);
    }

    #[Test]
    public function it_validates_import_file_requirements()
    {
        Passport::actingAs($this->user);

        // Missing file
        $response = $this->postJson('/api/v1/bulk/users/import', [
            'format' => 'csv',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['file']);
    }

    #[Test]
    public function it_validates_export_format_requirements()
    {
        Passport::actingAs($this->user);

        // Missing format
        $response = $this->postJson('/api/v1/bulk/users/export', []);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['format']);
    }

    #[Test]
    public function it_can_parse_csv_file()
    {
        $csvContent = "email,name,password\ntest1@example.com,User 1,pass123\ntest2@example.com,User 2,pass456";
        $tempFile = tmpfile();
        fwrite($tempFile, $csvContent);
        $filePath = stream_get_meta_data($tempFile)['uri'];

        $service = new BulkImportService;
        $parser = $service->getParser('csv');

        $records = iterator_to_array($parser->parse($filePath));

        $this->assertCount(2, $records);
        $this->assertEquals('test1@example.com', $records[2]['email']);
        $this->assertEquals('User 2', $records[3]['name']);

        fclose($tempFile);
    }

    #[Test]
    public function it_can_parse_json_file()
    {
        $jsonContent = json_encode([
            'users' => [
                ['email' => 'test1@example.com', 'name' => 'User 1', 'password' => 'pass123'],
                ['email' => 'test2@example.com', 'name' => 'User 2', 'password' => 'pass456'],
            ],
        ]);

        $tempFile = tmpfile();
        fwrite($tempFile, $jsonContent);
        $filePath = stream_get_meta_data($tempFile)['uri'];

        $service = new BulkImportService;
        $parser = $service->getParser('json');

        $records = iterator_to_array($parser->parse($filePath));

        $this->assertCount(2, $records);
        $this->assertEquals('test1@example.com', $records[1]['email']);
        $this->assertEquals('User 2', $records[2]['name']);

        fclose($tempFile);
    }

    #[Test]
    public function it_enforces_organization_isolation()
    {
        $otherOrg = Organization::factory()->create();
        $otherUser = User::factory()->create([
            'organization_id' => $otherOrg->id,
        ]);

        $job = BulkImportJob::factory()->create([
            'organization_id' => $otherOrg->id,
            'created_by' => $otherUser->id,
        ]);

        Passport::actingAs($this->user);

        // User from different org should not see this job
        $response = $this->getJson("/api/v1/bulk/imports/{$job->id}");
        $response->assertStatus(403);
    }

    #[Test]
    public function it_can_cancel_pending_job()
    {
        Passport::actingAs($this->user);

        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'status' => 'pending',
        ]);

        $response = $this->postJson("/api/v1/bulk/imports/{$job->id}/cancel");

        $response->assertStatus(200);

        $job->refresh();
        $this->assertEquals('cancelled', $job->status);
    }

    #[Test]
    public function it_can_retry_failed_job()
    {
        Queue::fake();
        Passport::actingAs($this->user);

        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'status' => 'failed',
            'file_path' => 'imports/test.csv',
        ]);

        $response = $this->postJson("/api/v1/bulk/imports/{$job->id}/retry");

        $response->assertStatus(200);

        $job->refresh();
        $this->assertEquals('pending', $job->status);
    }

    #[Test]
    public function it_can_delete_completed_job()
    {
        Passport::actingAs($this->user);

        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'status' => 'completed',
        ]);

        $response = $this->deleteJson("/api/v1/bulk/imports/{$job->id}");

        $response->assertStatus(200);
        $this->assertDatabaseMissing('bulk_import_jobs', ['id' => $job->id]);
    }

    #[Test]
    public function it_cannot_delete_in_progress_job()
    {
        Passport::actingAs($this->user);

        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->user->id,
            'status' => 'processing',
        ]);

        $response = $this->deleteJson("/api/v1/bulk/imports/{$job->id}");

        $response->assertStatus(400);
        $this->assertDatabaseHas('bulk_import_jobs', ['id' => $job->id]);
    }
}
