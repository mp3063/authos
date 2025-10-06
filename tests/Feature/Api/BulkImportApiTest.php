<?php

namespace Tests\Feature\Api;

use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Tests\TestCase;

class BulkImportApiTest extends TestCase
{
    private User $user;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create();
        $this->user = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->user, ['users.manage']);
    }

    public function test_can_start_import(): void
    {
        Queue::fake();

        $csv = "email,name,role\nuser1@example.com,User One,user\nuser2@example.com,User Two,user";
        $file = UploadedFile::fake()->createWithContent('users.csv', $csv);

        $response = $this->postJson('/api/v1/bulk/import/users', [
            'file' => $file,
            'options' => [
                'send_invitations' => true,
                'duplicate_strategy' => 'skip',
            ],
        ]);

        $response->assertCreated()
            ->assertJsonStructure([
                'success',
                'data' => [
                    'id',
                    'type',
                    'status',
                    'total_records',
                ],
            ]);

        Queue::assertPushed(\App\Jobs\ProcessBulkImportJob::class);
    }

    public function test_validates_file_upload(): void
    {
        $response = $this->postJson('/api/v1/bulk/import/users', [
            'options' => ['send_invitations' => true],
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['file']);
    }

    public function test_can_list_import_jobs(): void
    {
        BulkImportJob::factory()
            ->for($this->organization)
            ->count(3)
            ->create(['type' => 'users']);

        $response = $this->getJson('/api/v1/bulk/import/jobs');

        $response->assertOk()
            ->assertJsonCount(3, 'data')
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'type',
                        'status',
                        'total_records',
                        'processed_records',
                        'created_at',
                    ],
                ],
            ]);
    }

    public function test_cannot_see_other_organizations_import_jobs(): void
    {
        $otherOrg = Organization::factory()->create();
        BulkImportJob::factory()->for($otherOrg)->count(2)->create();

        BulkImportJob::factory()->for($this->organization)->create();

        $response = $this->getJson('/api/v1/bulk/import/jobs');

        $response->assertOk()
            ->assertJsonCount(1, 'data');
    }

    public function test_can_get_import_status(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'total_records' => 100,
                'processed_records' => 75,
                'status' => 'processing',
            ]);

        $response = $this->getJson("/api/v1/bulk/import/jobs/{$job->id}");

        $response->assertOk()
            ->assertJsonPath('data.status', 'processing')
            ->assertJsonPath('data.progress', 75);
    }

    public function test_can_download_error_report(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'status' => 'completed_with_errors',
                'error_file_path' => 'errors/test.csv',
            ]);

        Storage::put('errors/test.csv', 'row,email,error\n1,invalid-email,Invalid email format');

        $response = $this->get("/api/v1/bulk/import/jobs/{$job->id}/errors");

        $response->assertOk()
            ->assertHeader('Content-Type', 'text/csv; charset=UTF-8');
    }

    public function test_can_start_export(): void
    {
        Queue::fake();

        $response = $this->postJson('/api/v1/bulk/export/users', [
            'format' => 'csv',
            'filters' => [
                'created_after' => '2024-01-01',
            ],
        ]);

        $response->assertCreated()
            ->assertJsonStructure([
                'success',
                'data' => [
                    'id',
                    'type',
                    'status',
                ],
            ]);

        Queue::assertPushed(\App\Jobs\ProcessBulkExportJob::class);
    }

    public function test_can_download_export(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'status' => 'completed',
                'file_path' => 'exports/users.csv',
            ]);

        Storage::put('exports/users.csv', 'email,name\nuser@example.com,User One');

        $response = $this->get("/api/v1/bulk/export/jobs/{$job->id}/download");

        $response->assertOk()
            ->assertHeader('Content-Type', 'text/csv; charset=UTF-8');
    }

    public function test_organization_isolation_for_import(): void
    {
        $otherOrg = Organization::factory()->create();
        $job = BulkImportJob::factory()->for($otherOrg)->create();

        $response = $this->getJson("/api/v1/bulk/import/jobs/{$job->id}");

        $response->assertNotFound();
    }

    public function test_validates_import_file_type(): void
    {
        $file = UploadedFile::fake()->create('users.txt');

        $response = $this->postJson('/api/v1/bulk/import/users', [
            'file' => $file,
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['file']);
    }

    public function test_validates_export_format(): void
    {
        $response = $this->postJson('/api/v1/bulk/export/users', [
            'format' => 'invalid',
        ]);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['format']);
    }

    public function test_can_cancel_import_job(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create(['status' => 'pending']);

        $response = $this->postJson("/api/v1/bulk/import/jobs/{$job->id}/cancel");

        $response->assertOk();

        $job->refresh();

        $this->assertEquals('cancelled', $job->status);
    }

    public function test_cannot_cancel_completed_job(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create(['status' => 'completed']);

        $response = $this->postJson("/api/v1/bulk/import/jobs/{$job->id}/cancel");

        $response->assertUnprocessable()
            ->assertJsonPath('message', 'Cannot cancel a completed job');
    }

    public function test_filters_import_jobs_by_status(): void
    {
        BulkImportJob::factory()
            ->for($this->organization)
            ->count(2)
            ->create(['status' => 'completed']);

        BulkImportJob::factory()
            ->for($this->organization)
            ->create(['status' => 'failed']);

        $response = $this->getJson('/api/v1/bulk/import/jobs?filter[status]=completed');

        $response->assertOk()
            ->assertJsonCount(2, 'data');
    }

    public function test_paginates_import_jobs(): void
    {
        BulkImportJob::factory()
            ->for($this->organization)
            ->count(25)
            ->create();

        $response = $this->getJson('/api/v1/bulk/import/jobs?per_page=10');

        $response->assertOk()
            ->assertJsonCount(10, 'data')
            ->assertJsonPath('meta.pagination.total', 25);
    }

    public function test_requires_authentication(): void
    {
        Passport::actingAs(User::factory()->create(), []);

        $response = $this->getJson('/api/v1/bulk/import/jobs');

        $response->assertForbidden();
    }
}
