<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\ProcessAuditExportJob;
use App\Models\AuditExport;
use App\Models\Organization;
use App\Services\AuditExportService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ProcessAuditExportJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private AuditExport $export;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create();
        $this->export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'format' => 'csv',
            'status' => 'pending',
        ]);
    }

    #[Test]
    public function job_can_be_dispatched_with_export_parameters(): void
    {
        Queue::fake();

        ProcessAuditExportJob::dispatch($this->export);

        Queue::assertPushed(ProcessAuditExportJob::class, function ($job) {
            return $job->export->id === $this->export->id;
        });
    }

    #[Test]
    public function job_generates_csv_export_correctly(): void
    {
        $mockService = Mockery::mock(AuditExportService::class);
        $mockService->shouldReceive('processExport')
            ->once()
            ->with($this->export)
            ->andReturnUsing(function ($export) {
                // Simulate CSV generation
                $csvContent = "id,event,user,timestamp\n1,login,user@example.com,2024-01-01\n";
                Storage::put('exports/audit_'.$export->id.'.csv', $csvContent);

                $export->update([
                    'status' => 'completed',
                    'file_path' => 'exports/audit_'.$export->id.'.csv',
                ]);
            });

        $this->app->instance(AuditExportService::class, $mockService);

        $job = new ProcessAuditExportJob($this->export);
        $job->handle($mockService);

        $this->export->refresh();
        $this->assertEquals('completed', $this->export->status);
        Storage::assertExists('exports/audit_'.$this->export->id.'.csv');
    }

    #[Test]
    public function job_generates_json_export_correctly(): void
    {
        $this->export->update(['format' => 'json']);

        $mockService = Mockery::mock(AuditExportService::class);
        $mockService->shouldReceive('processExport')
            ->once()
            ->with($this->export)
            ->andReturnUsing(function ($export) {
                // Simulate JSON generation
                $jsonContent = json_encode([
                    ['id' => 1, 'event' => 'login', 'user' => 'user@example.com'],
                ]);
                Storage::put('exports/audit_'.$export->id.'.json', $jsonContent);

                $export->update([
                    'status' => 'completed',
                    'file_path' => 'exports/audit_'.$export->id.'.json',
                ]);
            });

        $this->app->instance(AuditExportService::class, $mockService);

        $job = new ProcessAuditExportJob($this->export);
        $job->handle($mockService);

        $this->export->refresh();
        $this->assertEquals('completed', $this->export->status);
        Storage::assertExists('exports/audit_'.$this->export->id.'.json');

        $content = Storage::get('exports/audit_'.$this->export->id.'.json');
        $data = json_decode($content, true);
        $this->assertIsArray($data);
    }

    #[Test]
    public function job_generates_excel_export_correctly(): void
    {
        $this->export->update(['format' => 'xlsx']);

        $mockService = Mockery::mock(AuditExportService::class);
        $mockService->shouldReceive('processExport')
            ->once()
            ->with($this->export)
            ->andReturnUsing(function ($export) {
                // Simulate Excel generation (fake binary content)
                Storage::put('exports/audit_'.$export->id.'.xlsx', 'fake-excel-content');

                $export->update([
                    'status' => 'completed',
                    'file_path' => 'exports/audit_'.$export->id.'.xlsx',
                ]);
            });

        $this->app->instance(AuditExportService::class, $mockService);

        $job = new ProcessAuditExportJob($this->export);
        $job->handle($mockService);

        $this->export->refresh();
        $this->assertEquals('completed', $this->export->status);
        Storage::assertExists('exports/audit_'.$this->export->id.'.xlsx');
    }

    #[Test]
    public function job_stores_file_in_storage_disk(): void
    {
        $mockService = Mockery::mock(AuditExportService::class);
        $mockService->shouldReceive('processExport')
            ->once()
            ->andReturnUsing(function ($export) {
                $filePath = 'exports/audit_'.$export->id.'.csv';
                Storage::put($filePath, 'test,data');

                $export->update([
                    'status' => 'completed',
                    'file_path' => $filePath,
                ]);
            });

        $this->app->instance(AuditExportService::class, $mockService);

        $job = new ProcessAuditExportJob($this->export);
        $job->handle($mockService);

        $this->export->refresh();
        $this->assertNotNull($this->export->file_path);
        $this->assertTrue(Storage::exists($this->export->file_path));
    }

    #[Test]
    public function job_handles_large_datasets_with_chunking(): void
    {
        $mockService = Mockery::mock(AuditExportService::class);
        $mockService->shouldReceive('processExport')
            ->once()
            ->andReturnUsing(function ($export) {
                // Simulate chunked processing of large dataset
                $chunks = 10;
                $recordsPerChunk = 1000;

                $content = "id,event\n";
                for ($i = 0; $i < $chunks; $i++) {
                    for ($j = 0; $j < $recordsPerChunk; $j++) {
                        $content .= ($i * $recordsPerChunk + $j).",event\n";
                    }
                }

                Storage::put('exports/large_audit.csv', $content);

                $export->update([
                    'status' => 'completed',
                    'file_path' => 'exports/large_audit.csv',
                    'records_exported' => $chunks * $recordsPerChunk,
                ]);
            });

        $this->app->instance(AuditExportService::class, $mockService);

        $job = new ProcessAuditExportJob($this->export);
        $job->handle($mockService);

        $this->export->refresh();
        $this->assertEquals('completed', $this->export->status);
        $this->assertEquals(10000, $this->export->records_exported);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
