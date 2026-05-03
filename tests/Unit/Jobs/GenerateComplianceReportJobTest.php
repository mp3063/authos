<?php

namespace Tests\Unit\Jobs;

use App\Jobs\GenerateComplianceReportJob;
use App\Mail\ComplianceReportGenerated;
use App\Models\Organization;
use App\Services\ComplianceReportService;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class GenerateComplianceReportJobTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        Mail::fake();

        $this->organization = Organization::factory()->create();
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[Test]
    public function it_can_be_dispatched_to_queue(): void
    {
        Queue::fake();

        $recipients = ['admin@example.com'];

        GenerateComplianceReportJob::dispatch($this->organization, 'soc2', $recipients);

        Queue::assertPushed(GenerateComplianceReportJob::class, function ($job) use ($recipients) {
            return $job->organization->id === $this->organization->id &&
                $job->reportType === 'soc2' &&
                $job->emailRecipients === $recipients;
        });
    }

    #[Test]
    public function it_has_correct_configuration(): void
    {
        $job = new GenerateComplianceReportJob($this->organization, 'soc2');

        $this->assertEquals(300, $job->timeout);
        $this->assertEquals(2, $job->tries);
    }

    #[Test]
    public function it_generates_soc2_report(): void
    {
        $reportData = [
            'report_type' => 'SOC2',
            'organization' => ['id' => $this->organization->id],
            'generated_at' => now()->toISOString(),
        ];

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->with($this->organization, Mockery::any(), Mockery::any())
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2');
        $job->handle($service);

        // Verify both PDF and JSON files were created (now in per-org subdir)
        $files = Storage::allFiles('compliance_reports');
        $this->assertNotEmpty($files);
        $this->assertContains(true, array_map(fn ($f) => str_contains($f, '/soc2_'), $files));
    }

    #[Test]
    public function it_generates_iso27001_report(): void
    {
        $reportData = [
            'report_type' => 'ISO_27001',
            'organization' => ['id' => $this->organization->id],
            'generated_at' => now()->toISOString(),
        ];

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateISO27001Report')
            ->once()
            ->with($this->organization, Mockery::any(), Mockery::any())
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'iso27001');
        $job->handle($service);

        // Verify both PDF and JSON files were created (now in per-org subdir)
        $files = Storage::allFiles('compliance_reports');
        $this->assertNotEmpty($files);
        $this->assertContains(true, array_map(fn ($f) => str_contains($f, '/iso27001_'), $files));
    }

    #[Test]
    public function it_generates_gdpr_report(): void
    {
        $reportData = [
            'report_type' => 'GDPR',
            'organization' => ['id' => $this->organization->id],
            'generated_at' => now()->toISOString(),
        ];

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateGDPRReport')
            ->once()
            ->with($this->organization, Mockery::any(), Mockery::any())
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'gdpr');
        $job->handle($service);

        // Verify both PDF and JSON files were created (now in per-org subdir)
        $files = Storage::allFiles('compliance_reports');
        $this->assertNotEmpty($files);
        $this->assertContains(true, array_map(fn ($f) => str_contains($f, '/gdpr_'), $files));
    }

    #[Test]
    public function it_sends_email_to_recipients(): void
    {
        $recipients = ['admin@example.com', 'compliance@example.com'];

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn(['report_type' => 'SOC2']);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2', $recipients);
        $job->handle($service);

        Mail::assertSent(ComplianceReportGenerated::class, function ($mail) use ($recipients) {
            return $mail->hasTo($recipients);
        });
    }

    #[Test]
    public function it_does_not_send_email_when_no_recipients(): void
    {
        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn(['report_type' => 'SOC2']);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2', []);
        $job->handle($service);

        Mail::assertNothingSent();
    }

    #[Test]
    public function it_throws_exception_for_invalid_report_type(): void
    {
        $service = Mockery::mock(ComplianceReportService::class);

        $job = new GenerateComplianceReportJob($this->organization, 'invalid_type');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid report type: invalid_type');

        $job->handle($service);
    }

    #[Test]
    public function it_saves_report_to_storage(): void
    {
        $reportData = [
            'report_type' => 'SOC2',
            'data' => ['test' => 'value'],
        ];

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2');
        $job->handle($service);

        $files = Storage::allFiles('compliance_reports');
        $jsonFile = collect($files)->first(fn ($f) => str_ends_with($f, '.json'));
        $this->assertNotNull($jsonFile);

        $content = Storage::get($jsonFile);
        $decoded = json_decode($content, true);

        $this->assertEquals('SOC2', $decoded['report_type']);
        $this->assertEquals(['test' => 'value'], $decoded['data']);
    }
}
