<?php

namespace Tests\Unit\Jobs;

use App\Jobs\ProcessAuditExportJob;
use App\Models\AuditExport;
use App\Models\Organization;
use App\Models\User;
use App\Services\AuditExportService;
use Exception;
use Illuminate\Support\Facades\Queue;
use Mockery;
use Tests\TestCase;

class ProcessAuditExportJobTest extends TestCase
{
    private AuditExport $export;

    private Organization $organization;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $this->export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
            'status' => 'pending',
        ]);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_can_be_dispatched_to_queue(): void
    {
        Queue::fake();

        ProcessAuditExportJob::dispatch($this->export);

        Queue::assertPushed(ProcessAuditExportJob::class, function ($job) {
            return $job->export->id === $this->export->id;
        });
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_has_correct_configuration(): void
    {
        $job = new ProcessAuditExportJob($this->export);

        $this->assertEquals(600, $job->timeout);
        $this->assertEquals(2, $job->tries);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calls_service_process_export(): void
    {
        $service = Mockery::mock(AuditExportService::class);
        $service->shouldReceive('processExport')
            ->once()
            ->with(Mockery::on(function ($export) {
                return $export->id === $this->export->id;
            }))
            ->andReturnNull();

        $job = new ProcessAuditExportJob($this->export);
        $job->handle($service);

        // Service was called successfully
        $this->assertTrue(true);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_processing_failure(): void
    {
        $service = Mockery::mock(AuditExportService::class);
        $service->shouldReceive('processExport')
            ->once()
            ->andThrow(new Exception('Export processing failed'));

        $job = new ProcessAuditExportJob($this->export);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Export processing failed');

        $job->handle($service);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_export_status_on_failure(): void
    {
        $service = Mockery::mock(AuditExportService::class);
        $service->shouldReceive('processExport')
            ->once()
            ->andThrow(new Exception('Processing error'));

        $job = new ProcessAuditExportJob($this->export);

        try {
            $job->handle($service);
        } catch (Exception $e) {
            // Expected
        }

        $this->export->refresh();
        $this->assertEquals('failed', $this->export->status);
        $this->assertEquals('Processing error', $this->export->error_message);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calls_failed_method_on_permanent_failure(): void
    {
        $exception = new Exception('Permanent export failure');

        $job = new ProcessAuditExportJob($this->export);
        $job->failed($exception);

        $this->export->refresh();
        $this->assertEquals('failed', $this->export->status);
        $this->assertEquals('Permanent export failure', $this->export->error_message);
    }
}
