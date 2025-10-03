<?php

namespace App\Jobs;

use App\Models\AuditExport;
use App\Services\AuditExportService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ProcessAuditExportJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 600; // 10 minutes

    public int $tries = 2;

    public function __construct(
        public AuditExport $export
    ) {}

    public function handle(AuditExportService $service): void
    {
        Log::info("Processing audit export: {$this->export->id}");

        try {
            // Process the export using the service
            $service->processExport($this->export);

            Log::info("Audit export completed: {$this->export->id}");

        } catch (\Exception $e) {
            Log::error("Audit export failed: {$e->getMessage()}");

            $this->export->update([
                'status' => 'failed',
                'error_message' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    public function failed(\Throwable $exception): void
    {
        Log::error("Audit export job failed: {$exception->getMessage()}");

        $this->export->update([
            'status' => 'failed',
            'error_message' => $exception->getMessage(),
        ]);
    }
}
