<?php

namespace App\Jobs;

use App\Mail\ComplianceReportGenerated;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Services\Compliance\CompliancePdfRenderer;
use App\Services\ComplianceReportService;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Throwable;

class GenerateComplianceReportJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $timeout = 300;

    public int $tries = 2;

    /** @var array<int, int> */
    public array $backoff = [60, 300];

    public function __construct(
        public Organization $organization,
        public string $reportType,
        public array $emailRecipients = [],
        public ?int $scheduledReportId = null,
        public ?CarbonInterface $periodStart = null,
        public ?CarbonInterface $periodEnd = null,
        public ?int $generatedByUserId = null,
    ) {}

    public function middleware(): array
    {
        // One PDF generation per (org, type) at a time. Prevents disk thrash
        // and double-billed renders if the queue retries.
        return [(new WithoutOverlapping("compliance:{$this->organization->id}:{$this->reportType}"))->expireAfter(600)];
    }

    public function handle(ComplianceReportService $service, ?CompliancePdfRenderer $renderer = null): void
    {
        $renderer ??= app(CompliancePdfRenderer::class);

        $start = $this->periodStart ? CarbonImmutable::instance($this->periodStart) : CarbonImmutable::now()->subDays(30);
        $end = $this->periodEnd ? CarbonImmutable::instance($this->periodEnd) : CarbonImmutable::now();

        $report = ComplianceReport::create([
            'organization_id' => $this->organization->id,
            'generated_by_user_id' => $this->generatedByUserId,
            'scheduled_report_id' => $this->scheduledReportId,
            'report_type' => $this->reportType,
            'status' => ComplianceReport::STATUS_GENERATING,
            'period_start' => $start->toDateString(),
            'period_end' => $end->toDateString(),
        ]);

        Log::info('Generating compliance report', [
            'report_id' => $report->id,
            'organization_id' => $this->organization->id,
            'report_type' => $this->reportType,
        ]);

        try {
            $reportData = match ($this->reportType) {
                ComplianceReport::TYPE_SOC2 => $service->generateSOC2Report($this->organization, $start, $end),
                ComplianceReport::TYPE_ISO27001 => $service->generateISO27001Report($this->organization, $start, $end),
                ComplianceReport::TYPE_GDPR => $service->generateGDPRReport($this->organization, $start, $end),
                default => throw new \InvalidArgumentException("Invalid report type: {$this->reportType}"),
            };

            $jsonPath = sprintf(
                'compliance_reports/%d/%s_%s_%s.json',
                $this->organization->id,
                $this->reportType,
                now()->format('Ymd'),
                (string) Str::uuid(),
            );
            Storage::disk('local')->put($jsonPath, json_encode($reportData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            $pdfPath = $renderer->render($this->reportType, $reportData, $this->organization);

            $report->update([
                'status' => ComplianceReport::STATUS_COMPLETED,
                'file_path_pdf' => $pdfPath,
                'file_path_json' => $jsonPath,
                'generated_at' => now(),
                'expires_at' => now()->addDays((int) config('compliance.report_retention_days', 180)),
                'summary' => $this->extractSummary($reportData),
            ]);

            if (! empty($this->emailRecipients)) {
                Mail::to($this->emailRecipients)->send(new ComplianceReportGenerated(
                    $this->organization,
                    $this->reportType,
                    $reportData,
                    $report->pdfDownloadUrl() ?? '',
                    Storage::disk('local')->path($pdfPath),
                    Storage::disk('local')->path($jsonPath),
                ));
            }

            Log::info('Compliance report generated', [
                'report_id' => $report->id,
                'pdf_path' => $pdfPath,
                'json_path' => $jsonPath,
            ]);
        } catch (Throwable $e) {
            $report->update([
                'status' => ComplianceReport::STATUS_FAILED,
                'error_message' => $e->getMessage(),
                'generated_at' => now(),
            ]);

            Log::error('Compliance report generation failed', [
                'report_id' => $report->id,
                'organization_id' => $this->organization->id,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    public function failed(Throwable $exception): void
    {
        Log::error('Compliance report job failed', [
            'organization_id' => $this->organization->id,
            'report_type' => $this->reportType,
            'error' => $exception->getMessage(),
        ]);
    }

    /**
     * Flat scalar key-value pairs only — consumed by ComplianceReport.summary,
     * which is rendered by Filament KeyValueEntry-style widgets that cannot
     * format nested arrays.
     */
    private function extractSummary(array $reportData): array
    {
        $period = $reportData['period'] ?? [];

        return [
            'report_type' => $reportData['report_type'] ?? null,
            'period_from' => $period['from'] ?? null,
            'period_to' => $period['to'] ?? null,
            'period_days' => isset($period['days']) ? (int) round((float) $period['days']) : null,
            'total_users' => $reportData['access_controls']['total_users']
                ?? $reportData['data_subjects_count']
                ?? null,
            'mfa_adoption_rate' => $reportData['mfa_adoption']['adoption_rate_percentage'] ?? null,
            'open_critical_incidents' => $reportData['incident_management']['open_critical_count'] ?? null,
            'consent_coverage_percentage' => $reportData['consent_tracking']['consent_coverage_percentage'] ?? null,
        ];
    }
}
