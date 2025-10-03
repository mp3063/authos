<?php

namespace Tests\Unit\Services;

use App\Jobs\ProcessAuditExportJob;
use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\AuditExportService;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class AuditExportServiceTest extends TestCase
{
    private AuditExportService $service;

    private Organization $organization;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('public');

        $this->service = new AuditExportService;
        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_create_export_async_dispatches_job(): void
    {
        Queue::fake();

        $export = $this->service->createExportAsync(
            $this->organization->id,
            $this->user->id,
            ['date_from' => '2024-01-01'],
            'csv'
        );

        $this->assertInstanceOf(AuditExport::class, $export);
        $this->assertEquals('pending', $export->status);
        $this->assertEquals($this->organization->id, $export->organization_id);
        $this->assertEquals($this->user->id, $export->user_id);
        $this->assertEquals('csv', $export->type);

        Queue::assertPushed(ProcessAuditExportJob::class);
    }

    public function test_create_export_creates_export_record(): void
    {
        $filters = [
            'date_from' => '2024-01-01',
            'date_to' => '2024-01-31',
            'event' => 'login',
        ];

        $export = $this->service->createExport(
            $this->organization->id,
            $this->user->id,
            $filters,
            'json'
        );

        $this->assertDatabaseHas('audit_exports', [
            'id' => $export->id,
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'json',
            'status' => 'pending',
        ]);

        $this->assertEquals($filters, $export->filters);
    }

    public function test_process_export_creates_json_file(): void
    {
        AuthenticationLog::factory()->count(5)->create([
            'user_id' => $this->user->id,
        ]);

        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'json',
            'status' => 'pending',
        ]);

        $this->service->processExport($export);

        $export->refresh();

        $this->assertEquals('completed', $export->status);
        $this->assertNotNull($export->file_path);
        $this->assertNotNull($export->completed_at);
        $this->assertEquals(5, $export->records_count);
        Storage::disk('public')->assertExists($export->file_path);
    }

    public function test_process_export_filters_by_date_range(): void
    {
        // Create logs within date range
        AuthenticationLog::factory()->count(3)->create([
            'user_id' => $this->user->id,
            'created_at' => '2024-01-15',
        ]);

        // Create logs outside date range
        AuthenticationLog::factory()->count(2)->create([
            'user_id' => $this->user->id,
            'created_at' => '2024-02-15',
        ]);

        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'json',
            'status' => 'pending',
            'filters' => [
                'date_from' => '2024-01-01',
                'date_to' => '2024-01-31',
            ],
        ]);

        $this->service->processExport($export);

        $export->refresh();

        $this->assertEquals(3, $export->records_count);
    }

    public function test_process_export_filters_by_event_type(): void
    {
        AuthenticationLog::factory()->count(2)->create([
            'user_id' => $this->user->id,
            'event' => 'login',
        ]);

        AuthenticationLog::factory()->count(3)->create([
            'user_id' => $this->user->id,
            'event' => 'logout',
        ]);

        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'json',
            'status' => 'pending',
            'filters' => [
                'event' => 'login',
            ],
        ]);

        $this->service->processExport($export);

        $export->refresh();

        $this->assertEquals(2, $export->records_count);
    }

    public function test_process_export_filters_by_user(): void
    {
        $targetUser = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        AuthenticationLog::factory()->count(3)->create([
            'user_id' => $targetUser->id,
        ]);

        AuthenticationLog::factory()->count(2)->create([
            'user_id' => $this->user->id,
        ]);

        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'json',
            'status' => 'pending',
            'filters' => [
                'user_id' => $targetUser->id,
            ],
        ]);

        $this->service->processExport($export);

        $export->refresh();

        $this->assertEquals(3, $export->records_count);
    }

    public function test_process_export_filters_by_success_status(): void
    {
        AuthenticationLog::factory()->count(4)->create([
            'user_id' => $this->user->id,
            'success' => true,
        ]);

        AuthenticationLog::factory()->count(2)->create([
            'user_id' => $this->user->id,
            'success' => false,
        ]);

        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'json',
            'status' => 'pending',
            'filters' => [
                'success' => false,
            ],
        ]);

        $this->service->processExport($export);

        $export->refresh();

        $this->assertEquals(2, $export->records_count);
    }

    public function test_process_export_handles_failure(): void
    {
        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'type' => 'invalid_type',
            'status' => 'pending',
        ]);

        $this->service->processExport($export);

        $export->refresh();

        $this->assertEquals('failed', $export->status);
        $this->assertNotNull($export->error_message);
        $this->assertNotNull($export->completed_at);
    }

    public function test_get_exports_returns_paginated_results(): void
    {
        AuditExport::factory()->count(20)->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
        ]);

        $result = $this->service->getExports($this->organization->id, 10);

        $this->assertCount(10, $result);
        $this->assertEquals(20, $result->total());
    }

    public function test_get_exports_includes_user_relationship(): void
    {
        AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
        ]);

        $result = $this->service->getExports($this->organization->id);

        $this->assertTrue($result->first()->relationLoaded('user'));
        $this->assertNotNull($result->first()->user);
    }

    public function test_cleanup_old_exports_deletes_old_records(): void
    {
        // Create old exports
        $oldExport1 = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'created_at' => now()->subDays(40),
            'file_path' => 'exports/old-export-1.json',
        ]);

        $oldExport2 = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'created_at' => now()->subDays(35),
            'file_path' => 'exports/old-export-2.json',
        ]);

        // Create recent export
        $recentExport = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'created_at' => now()->subDays(10),
        ]);

        // Create export files
        Storage::disk('public')->put($oldExport1->file_path, 'test content');
        Storage::disk('public')->put($oldExport2->file_path, 'test content');

        $deleted = $this->service->cleanupOldExports(30);

        $this->assertEquals(2, $deleted);
        $this->assertDatabaseMissing('audit_exports', ['id' => $oldExport1->id]);
        $this->assertDatabaseMissing('audit_exports', ['id' => $oldExport2->id]);
        $this->assertDatabaseHas('audit_exports', ['id' => $recentExport->id]);
        Storage::disk('public')->assertMissing($oldExport1->file_path);
        Storage::disk('public')->assertMissing($oldExport2->file_path);
    }
}
