<?php

namespace Tests\Integration\Enterprise;

use App\Jobs\GenerateComplianceReportJob;
use App\Mail\ComplianceReportGenerated;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Services\Compliance\CompliancePdfRenderer;
use App\Services\ComplianceReportService;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class CompliancePdfGenerationTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake('local');
        Storage::fake('public');
        Mail::fake();
        $this->organization = Organization::factory()->create();
    }

    #[Test]
    public function job_creates_compliance_report_row_and_writes_pdf_and_json(): void
    {
        $job = new GenerateComplianceReportJob($this->organization, 'soc2');

        $job->handle(
            app(ComplianceReportService::class),
            app(CompliancePdfRenderer::class),
        );

        $report = ComplianceReport::query()->latest('id')->first();
        $this->assertNotNull($report);
        $this->assertSame(ComplianceReport::STATUS_COMPLETED, $report->status);
        $this->assertSame('soc2', $report->report_type);
        $this->assertNotNull($report->file_path_pdf);
        $this->assertNotNull($report->file_path_json);
        $this->assertNotNull($report->generated_at);
        $this->assertNotNull($report->expires_at);
        $this->assertIsArray($report->summary);

        $this->assertTrue(Storage::disk('local')->exists($report->file_path_pdf));
        $this->assertTrue(Storage::disk('local')->exists($report->file_path_json));

        $pdfBytes = Storage::disk('local')->get($report->file_path_pdf);
        $this->assertStringStartsWith('%PDF-', (string) $pdfBytes);
        $this->assertGreaterThan(1024, strlen((string) $pdfBytes));

        $jsonContent = Storage::disk('local')->get($report->file_path_json);
        $decoded = json_decode((string) $jsonContent, true);
        $this->assertIsArray($decoded);
        $this->assertSame('SOC2', $decoded['report_type']);
    }

    #[Test]
    public function job_emails_recipients_with_attachments(): void
    {
        $job = new GenerateComplianceReportJob(
            $this->organization,
            'gdpr',
            ['compliance@example.com'],
        );

        $job->handle(
            app(ComplianceReportService::class),
            app(CompliancePdfRenderer::class),
        );

        Mail::assertSent(ComplianceReportGenerated::class, function ($mail) {
            return $mail->hasTo('compliance@example.com')
                && $mail->reportType === 'gdpr'
                && $mail->pdfFilesystemPath !== null
                && $mail->jsonFilesystemPath !== null;
        });
    }

    #[Test]
    public function job_marks_report_failed_on_renderer_exception(): void
    {
        $job = new GenerateComplianceReportJob($this->organization, 'badtype');

        try {
            $job->handle(
                app(ComplianceReportService::class),
                app(CompliancePdfRenderer::class),
            );
            $this->fail('Job should have thrown for invalid report type');
        } catch (\InvalidArgumentException) {
            // expected
        }

        $report = ComplianceReport::query()->latest('id')->first();
        $this->assertNotNull($report);
        $this->assertSame(ComplianceReport::STATUS_FAILED, $report->status);
        $this->assertNotNull($report->error_message);
    }
}
