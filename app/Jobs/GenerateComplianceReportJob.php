<?php

namespace App\Jobs;

use App\Mail\ComplianceReportGenerated;
use App\Models\Organization;
use App\Services\ComplianceReportService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;

class GenerateComplianceReportJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $timeout = 300; // 5 minutes

    public int $tries = 2;

    public function __construct(
        public Organization $organization,
        public string $reportType, // 'soc2', 'iso27001', 'gdpr'
        public array $emailRecipients = []
    ) {}

    public function handle(ComplianceReportService $service): void
    {
        Log::info("Generating {$this->reportType} report for org: {$this->organization->id}");

        try {
            // Generate report based on type
            $report = match ($this->reportType) {
                'soc2' => $service->generateSOC2Report($this->organization),
                'iso27001' => $service->generateISO27001Report($this->organization),
                'gdpr' => $service->generateGDPRReport($this->organization),
                default => throw new \InvalidArgumentException("Invalid report type: {$this->reportType}")
            };

            // Save report to storage
            $filename = "{$this->reportType}_report_{$this->organization->id}_".now()->format('Y-m-d').'.json';
            $path = "compliance_reports/{$filename}";
            Storage::put($path, json_encode($report, JSON_PRETTY_PRINT));

            // Send email if recipients provided
            if (! empty($this->emailRecipients)) {
                Mail::to($this->emailRecipients)->send(
                    new ComplianceReportGenerated(
                        $this->organization,
                        $this->reportType,
                        $report,
                        Storage::url($path)
                    )
                );
            }

            Log::info("Compliance report generated: {$path}");

        } catch (\Exception $e) {
            Log::error("Compliance report generation failed: {$e->getMessage()}");
            throw $e;
        }
    }

    public function failed(\Throwable $exception): void
    {
        Log::error("Compliance report job failed: {$exception->getMessage()}");
    }
}
