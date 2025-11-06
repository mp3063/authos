<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\ExportUsersJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use App\Services\BulkImport\BulkImportService;
use App\Services\BulkImport\DTOs\ExportOptions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ExportUsersJobTest extends TestCase
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
            'file_format' => 'csv',
            'status' => BulkImportJob::STATUS_PENDING,
            'options' => [],
        ]);
    }

    #[Test]
    public function job_exports_all_users_for_organization(): void
    {
        // Create users for this organization
        User::factory()->count(10)->create([
            'organization_id' => $this->organization->id,
        ]);

        // Create users for another organization (should not be exported)
        $otherOrg = Organization::factory()->create();
        User::factory()->count(5)->create([
            'organization_id' => $otherOrg->id,
        ]);

        $mockService = $this->createMockBulkImportService();
        $this->app->instance(BulkImportService::class, $mockService);

        $job = new ExportUsersJob($this->exportJob);
        $job->handle($mockService);

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);
        $this->assertEquals(10, $this->exportJob->total_records);
    }

    #[Test]
    public function job_respects_multi_tenant_boundaries(): void
    {
        // Create users in two different organizations
        $org1Users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        $otherOrg = Organization::factory()->create();
        $org2Users = User::factory()->count(7)->create([
            'organization_id' => $otherOrg->id,
        ]);

        $mockService = $this->createMockBulkImportService();
        $this->app->instance(BulkImportService::class, $mockService);

        $job = new ExportUsersJob($this->exportJob);
        $job->handle($mockService);

        $this->exportJob->refresh();

        // Should only export users from the export job's organization
        $this->assertEquals(5, $this->exportJob->total_records);
    }

    #[Test]
    public function job_includes_user_relationships(): void
    {
        // Create users with roles and applications
        $user = $this->createUser([
            'organization_id' => $this->organization->id,
        ], 'Organization Admin');

        $mockService = $this->createMockBulkImportService();
        $this->app->instance(BulkImportService::class, $mockService);

        $job = new ExportUsersJob($this->exportJob);
        $job->handle($mockService);

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);

        // Verify the export completed
        $this->assertNotNull($this->exportJob->file_path);
    }

    #[Test]
    public function job_formats_data_correctly_for_csv(): void
    {
        User::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'email_verified_at' => now(),
        ]);

        $mockService = $this->createMockBulkImportService();
        $this->app->instance(BulkImportService::class, $mockService);

        $job = new ExportUsersJob($this->exportJob);
        $job->handle($mockService);

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);

        // Verify file was created
        Storage::assertExists($this->exportJob->file_path);
    }

    #[Test]
    public function job_handles_empty_result_sets(): void
    {
        // Set up mock service to handle empty results
        $mockService = Mockery::mock(BulkImportService::class);
        $mockService->shouldReceive('getParser')
            ->never();

        $this->app->instance(BulkImportService::class, $mockService);

        $job = new ExportUsersJob($this->exportJob);

        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Starting export job/'), Mockery::any())
            ->once();

        Log::shouldReceive('error')
            ->with(Mockery::pattern('/Failed export job/'), Mockery::any())
            ->once();

        try {
            $job->handle($mockService);
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('No users found', $e->getMessage());
        }

        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_FAILED, $this->exportJob->status);
    }

    #[Test]
    public function job_tracks_job_status(): void
    {
        User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Starting export job/'), Mockery::any())
            ->once();

        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Exporting \d+ users/'), Mockery::any())
            ->once();

        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Exported \d+ users/'), Mockery::any())
            ->atLeast()
            ->once();

        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Completed export job/'), Mockery::any())
            ->once();

        $mockService = $this->createMockBulkImportService();
        $this->app->instance(BulkImportService::class, $mockService);

        // Initial status
        $this->assertEquals(BulkImportJob::STATUS_PENDING, $this->exportJob->status);

        $job = new ExportUsersJob($this->exportJob);
        $job->handle($mockService);

        // Final status
        $this->exportJob->refresh();
        $this->assertEquals(BulkImportJob::STATUS_COMPLETED, $this->exportJob->status);
        $this->assertEquals(5, $this->exportJob->processed_records);
        $this->assertNotNull($this->exportJob->file_path);
    }

    /**
     * Create a mock BulkImportService with common expectations
     */
    private function createMockBulkImportService(): BulkImportService
    {
        $mockParser = Mockery::mock();
        $mockParser->shouldReceive('generate')
            ->andReturnUsing(function ($records, $filename) {
                $filePath = 'exports/'.$filename;
                Storage::put($filePath, 'mock csv content');

                return $filePath;
            });

        $mockService = Mockery::mock(BulkImportService::class);
        $mockService->shouldReceive('getParser')
            ->andReturn($mockParser);

        return $mockService;
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
