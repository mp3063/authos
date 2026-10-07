<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\GenerateComplianceReportJob;
use App\Mail\ComplianceReportGenerated;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Services\ComplianceReportService;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
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
        $start = CarbonImmutable::parse('2026-01-01');
        $end = CarbonImmutable::parse('2026-03-31');

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->with(
                Mockery::on(fn ($org) => $org->is($this->organization)),
                Mockery::on(fn ($from) => $from->toDateString() === '2026-01-01'),
                Mockery::on(fn ($to) => $to->toDateString() === '2026-03-31'),
            )
            ->andReturn(['report_type' => 'SOC2', 'organization' => $this->organization->name]);

        (new GenerateComplianceReportJob($this->organization, 'soc2', periodStart: $start, periodEnd: $end))->handle($service);

        $report = $this->latestReport();
        $this->assertSame(ComplianceReport::STATUS_COMPLETED, $report->status);
        $this->assertSame('2026-01-01', $report->period_start->toDateString());
        $this->assertSame('2026-03-31', $report->period_end->toDateString());
        $this->assertSame('SOC2', $this->storedJson($report)['report_type']);
        $this->assertSame($this->organization->name, $this->storedJson($report)['organization']);
    }

    #[Test]
    public function job_generates_iso27001_report(): void
    {
        $service = $this->mockService('generateISO27001Report', ['report_type' => 'ISO27001']);

        (new GenerateComplianceReportJob($this->organization, 'iso27001'))->handle($service);

        $report = $this->latestReport();
        $this->assertSame(ComplianceReport::TYPE_ISO27001, $report->report_type);
        $this->assertSame(ComplianceReport::STATUS_COMPLETED, $report->status);
        $this->assertSame('ISO27001', $this->storedJson($report)['report_type']);
    }

    #[Test]
    public function job_generates_gdpr_report(): void
    {
        $service = $this->mockService('generateGDPRReport', [
            'report_type' => 'GDPR',
            'compliance_areas' => ['data_protection' => ['status' => 'compliant']],
        ]);

        (new GenerateComplianceReportJob($this->organization, 'gdpr'))->handle($service);

        $report = $this->latestReport();
        $this->assertSame(ComplianceReport::STATUS_COMPLETED, $report->status);
        $this->assertSame('GDPR', $this->storedJson($report)['report_type']);
        $this->assertArrayHasKey('compliance_areas', $this->storedJson($report));
    }

    #[Test]
    public function job_defaults_to_the_last_30_days_when_no_period_given(): void
    {
        CarbonImmutable::setTestNow('2026-06-30 12:00:00');

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->with(
                Mockery::any(),
                Mockery::on(fn ($from) => $from->toDateString() === '2026-05-31'),
                Mockery::on(fn ($to) => $to->toDateString() === '2026-06-30'),
            )
            ->andReturn(['report_type' => 'SOC2']);

        (new GenerateComplianceReportJob($this->organization, 'soc2'))->handle($service);

        $report = $this->latestReport();
        $this->assertSame('2026-05-31', $report->period_start->toDateString());
        $this->assertSame('2026-06-30', $report->period_end->toDateString());
    }

    #[Test]
    public function job_includes_all_required_sections(): void
    {
        $service = $this->mockService('generateSOC2Report', [
            'report_type' => 'SOC2',
            'period' => ['from' => '2026-01-01', 'to' => '2026-01-31', 'days' => 30.4],
            'access_controls' => ['total_users' => 42],
            'mfa_adoption' => ['adoption_rate_percentage' => 87.5],
            'incident_management' => ['open_critical_count' => 1],
            'generated_at' => now()->toDateTimeString(),
        ]);

        (new GenerateComplianceReportJob($this->organization, 'soc2'))->handle($service);

        $report = $this->latestReport();
        $json = $this->storedJson($report);
        $this->assertArrayHasKey('access_controls', $json);
        $this->assertArrayHasKey('mfa_adoption', $json);
        $this->assertArrayHasKey('generated_at', $json);

        $this->assertSame('SOC2', $report->summary['report_type']);
        $this->assertSame(30, $report->summary['period_days']);
        $this->assertSame(42, $report->summary['total_users']);
        $this->assertEquals(87.5, $report->summary['mfa_adoption_rate']);
        $this->assertSame(1, $report->summary['open_critical_incidents']);
    }

    #[Test]
    public function job_emails_report_to_recipients(): void
    {
        $recipients = ['admin@example.com', 'compliance@example.com'];
        $service = $this->mockService('generateSOC2Report', ['report_type' => 'SOC2']);

        (new GenerateComplianceReportJob($this->organization, 'soc2', $recipients))->handle($service);

        Mail::assertSent(ComplianceReportGenerated::class, function ($mail) use ($recipients) {
            return $mail->hasTo($recipients[0]) &&
                   $mail->hasTo($recipients[1]);
        });
    }

    #[Test]
    public function job_stores_report_in_storage(): void
    {
        $service = $this->mockService('generateSOC2Report', ['report_type' => 'SOC2', 'data' => 'test report data']);

        (new GenerateComplianceReportJob($this->organization, 'soc2'))->handle($service);

        $report = $this->latestReport();
        $prefix = "compliance_reports/{$this->organization->id}/soc2_".now()->format('Ymd').'_';

        $this->assertStringStartsWith($prefix, $report->file_path_json);
        $this->assertStringEndsWith('.json', $report->file_path_json);
        Storage::disk('local')->assertExists($report->file_path_json);

        $this->assertNotNull($report->file_path_pdf);
        Storage::disk('local')->assertExists($report->file_path_pdf);
        $this->assertStringStartsWith('%PDF', Storage::disk('local')->get($report->file_path_pdf));

        $this->assertNotNull($report->expires_at);
    }

    #[Test]
    public function job_marks_report_failed_and_rethrows_when_generation_fails(): void
    {
        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')->once()->andThrow(new RuntimeException('Data source unavailable'));

        try {
            (new GenerateComplianceReportJob($this->organization, 'soc2', ['admin@example.com']))->handle($service);
            $this->fail('Expected the job to rethrow the generation error.');
        } catch (RuntimeException $e) {
            $this->assertSame('Data source unavailable', $e->getMessage());
        }

        $report = $this->latestReport();
        $this->assertSame(ComplianceReport::STATUS_FAILED, $report->status);
        $this->assertSame('Data source unavailable', $report->error_message);
        $this->assertNull($report->file_path_json);
        Mail::assertNothingSent();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    private function mockService(string $method, array $reportData): ComplianceReportService&MockInterface
    {
        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive($method)->once()->andReturn($reportData);

        return $service;
    }

    private function latestReport(): ComplianceReport
    {
        return ComplianceReport::where('organization_id', $this->organization->id)->latest('id')->firstOrFail();
    }

    private function storedJson(ComplianceReport $report): array
    {
        return json_decode(Storage::disk('local')->get($report->file_path_json), true);
    }
}
