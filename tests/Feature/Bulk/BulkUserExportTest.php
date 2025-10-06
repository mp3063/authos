<?php

namespace Tests\Feature\Bulk;

use App\Jobs\ProcessBulkExportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class BulkUserExportTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create();

        User::factory()
            ->for($this->organization)
            ->count(10)
            ->create();
    }

    public function test_exports_users_to_csv(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertEquals('completed', $job->status);
        $this->assertNotNull($job->file_path);
        Storage::assertExists($job->file_path);

        $content = Storage::get($job->file_path);
        $this->assertStringContainsString('email', $content);
        $this->assertStringContainsString('name', $content);
    }

    public function test_exports_users_to_json(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'json',
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertEquals('completed', $job->status);
        Storage::assertExists($job->file_path);

        $content = Storage::get($job->file_path);
        $data = json_decode($content, true);

        $this->assertIsArray($data);
        $this->assertCount(10, $data);
        $this->assertArrayHasKey('email', $data[0]);
    }

    public function test_exports_with_filters(): void
    {
        User::factory()
            ->for($this->organization)
            ->create(['email_verified_at' => null]);

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
                'filters' => [
                    'email_verified' => true,
                ],
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $job->refresh();

        $content = Storage::get($job->file_path);
        $lines = explode("\n", $content);

        // Count lines (excluding header and empty line)
        $this->assertLessThan(12, count($lines));
    }

    public function test_exports_only_organization_users(): void
    {
        $otherOrg = Organization::factory()->create();
        User::factory()->for($otherOrg)->count(5)->create();

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $content = Storage::get($job->file_path);
        $lines = explode("\n", $content);

        // Should only export users from this organization (10 + header + empty line)
        $this->assertLessThanOrEqual(12, count($lines));
    }

    public function test_exports_selected_columns(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
                'columns' => ['email', 'name'],
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $content = Storage::get($job->file_path);
        $lines = explode("\n", $content);
        $header = str_getcsv($lines[0]);

        $this->assertContains('email', $header);
        $this->assertContains('name', $header);
        $this->assertNotContains('password', $header);
    }

    public function test_excludes_sensitive_fields(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $content = Storage::get($job->file_path);

        $this->assertStringNotContainsString('password', $content);
        $this->assertStringNotContainsString('two_factor_secret', $content);
        $this->assertStringNotContainsString('remember_token', $content);
    }

    public function test_handles_large_export(): void
    {
        User::factory()
            ->for($this->organization)
            ->count(500)
            ->create();

        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertEquals('completed', $job->status);
        Storage::assertExists($job->file_path);
    }

    public function test_tracks_export_progress(): void
    {
        $job = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $processor = new ProcessBulkExportJob($job);
        $processor->handle();

        $job->refresh();

        $this->assertNotNull($job->completed_at);
        $this->assertEquals('completed', $job->status);
    }

    public function test_sets_correct_file_extension(): void
    {
        $csvJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'csv',
            ]);

        $jsonJob = BulkImportJob::factory()
            ->for($this->organization)
            ->create([
                'type' => 'export',
                'export_type' => 'users',
                'format' => 'json',
            ]);

        (new ProcessBulkExportJob($csvJob))->handle();
        (new ProcessBulkExportJob($jsonJob))->handle();

        $this->assertStringEndsWith('.csv', $csvJob->fresh()->file_path);
        $this->assertStringEndsWith('.json', $jsonJob->fresh()->file_path);
    }
}
