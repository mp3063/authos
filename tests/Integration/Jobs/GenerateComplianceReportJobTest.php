<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\GenerateComplianceReportJob;
use App\Mail\ComplianceReportGenerated;
use App\Models\Organization;
use App\Services\ComplianceReportService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class GenerateComplianceReportJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        Mail::fake();

        $this->organization = Organization::factory()->create([
            'name' => 'Test Corp',
        ]);
    }

    #[Test]
    public function job_generates_soc2_compliance_report(): void
    {
        $mockService = Mockery::mock(ComplianceReportService::class);
        $mockService->shouldReceive('generateSOC2Report')
            ->once()
            ->with($this->organization)
            ->andReturn([
                'report_type' => 'SOC2',
                'organization' => $this->organization->name,
                'sections' => [
                    'security' => ['controls' => 10, 'compliant' => 10],
                    'availability' => ['controls' => 5, 'compliant' => 5],
                ],
                'generated_at' => now()->toDateTimeString(),
            ]);

        $this->app->instance(ComplianceReportService::class, $mockService);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2');
        $job->handle($mockService);

        $files = Storage::allFiles('compliance_reports');
        $this->assertCount(1, $files);

        $content = Storage::get($files[0]);
        $report = json_decode($content, true);

        $this->assertEquals('SOC2', $report['report_type']);
        $this->assertEquals($this->organization->name, $report['organization']);
    }

    #[Test]
    public function job_generates_iso27001_report(): void
    {
        $mockService = Mockery::mock(ComplianceReportService::class);
        $mockService->shouldReceive('generateISO27001Report')
            ->once()
            ->with($this->organization)
            ->andReturn([
                'report_type' => 'ISO27001',
                'organization' => $this->organization->name,
                'domains' => [
                    'information_security_policies' => ['compliant' => true],
                    'access_control' => ['compliant' => true],
                ],
                'generated_at' => now()->toDateTimeString(),
            ]);

        $this->app->instance(ComplianceReportService::class, $mockService);

        $job = new GenerateComplianceReportJob($this->organization, 'iso27001');
        $job->handle($mockService);

        $files = Storage::allFiles('compliance_reports');
        $this->assertCount(1, $files);

        $content = Storage::get($files[0]);
        $report = json_decode($content, true);

        $this->assertEquals('ISO27001', $report['report_type']);
    }

    #[Test]
    public function job_generates_gdpr_report(): void
    {
        $mockService = Mockery::mock(ComplianceReportService::class);
        $mockService->shouldReceive('generateGDPRReport')
            ->once()
            ->with($this->organization)
            ->andReturn([
                'report_type' => 'GDPR',
                'organization' => $this->organization->name,
                'compliance_areas' => [
                    'data_protection' => ['status' => 'compliant'],
                    'consent_management' => ['status' => 'compliant'],
                    'data_portability' => ['status' => 'compliant'],
                ],
                'generated_at' => now()->toDateTimeString(),
            ]);

        $this->app->instance(ComplianceReportService::class, $mockService);

        $job = new GenerateComplianceReportJob($this->organization, 'gdpr');
        $job->handle($mockService);

        $files = Storage::allFiles('compliance_reports');
        $this->assertCount(1, $files);

        $content = Storage::get($files[0]);
        $report = json_decode($content, true);

        $this->assertEquals('GDPR', $report['report_type']);
        $this->assertArrayHasKey('compliance_areas', $report);
    }

    #[Test]
    public function job_includes_all_required_sections(): void
    {
        $mockService = Mockery::mock(ComplianceReportService::class);
        $mockService->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn([
                'report_type' => 'SOC2',
                'organization' => $this->organization->name,
                'sections' => [
                    'security' => ['controls' => 10, 'compliant' => 10],
                    'availability' => ['controls' => 5, 'compliant' => 5],
                    'processing_integrity' => ['controls' => 3, 'compliant' => 3],
                    'confidentiality' => ['controls' => 7, 'compliant' => 7],
                    'privacy' => ['controls' => 8, 'compliant' => 8],
                ],
                'summary' => [
                    'total_controls' => 33,
                    'compliant_controls' => 33,
                    'compliance_percentage' => 100,
                ],
                'generated_at' => now()->toDateTimeString(),
            ]);

        $this->app->instance(ComplianceReportService::class, $mockService);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2');
        $job->handle($mockService);

        $files = Storage::allFiles('compliance_reports');
        $content = Storage::get($files[0]);
        $report = json_decode($content, true);

        $this->assertArrayHasKey('sections', $report);
        $this->assertArrayHasKey('summary', $report);
        $this->assertArrayHasKey('generated_at', $report);
    }

    #[Test]
    public function job_emails_report_to_recipients(): void
    {
        $recipients = ['admin@example.com', 'compliance@example.com'];

        $mockService = Mockery::mock(ComplianceReportService::class);
        $mockService->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn([
                'report_type' => 'SOC2',
                'organization' => $this->organization->name,
                'sections' => [],
                'generated_at' => now()->toDateTimeString(),
            ]);

        $this->app->instance(ComplianceReportService::class, $mockService);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2', $recipients);
        $job->handle($mockService);

        Mail::assertSent(ComplianceReportGenerated::class, function ($mail) use ($recipients) {
            return $mail->hasTo($recipients[0]) &&
                   $mail->hasTo($recipients[1]);
        });
    }

    #[Test]
    public function job_stores_report_in_storage(): void
    {
        $mockService = Mockery::mock(ComplianceReportService::class);
        $mockService->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn([
                'report_type' => 'SOC2',
                'data' => 'test report data',
            ]);

        $this->app->instance(ComplianceReportService::class, $mockService);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2');
        $job->handle($mockService);

        $files = Storage::allFiles('compliance_reports');
        $this->assertNotEmpty($files);

        $filename = $files[0];
        $this->assertStringContainsString('soc2_report', $filename);
        $this->assertStringContainsString((string) $this->organization->id, $filename);
        $this->assertStringContainsString(now()->format('Y-m-d'), $filename);

        Storage::assertExists($filename);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
