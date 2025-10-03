<?php

namespace Tests\Unit\Jobs;

use App\Jobs\GenerateComplianceReportJob;
use App\Models\Organization;
use App\Services\ComplianceReportService;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Mockery;
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_has_correct_configuration(): void
    {
        $job = new GenerateComplianceReportJob($this->organization, 'soc2');

        $this->assertEquals(300, $job->timeout);
        $this->assertEquals(2, $job->tries);
    }

    #[\PHPUnit\Framework\Attributes\Test]
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
            ->with($this->organization)
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2');
        $job->handle($service);

        // Verify file was created
        $files = Storage::files('compliance_reports');
        $this->assertCount(1, $files);
        $this->assertStringContainsString('soc2_report', $files[0]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
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
            ->with($this->organization)
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'iso27001');
        $job->handle($service);

        // Verify file was created
        $files = Storage::files('compliance_reports');
        $this->assertCount(1, $files);
        $this->assertStringContainsString('iso27001_report', $files[0]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
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
            ->with($this->organization)
            ->andReturn($reportData);

        $job = new GenerateComplianceReportJob($this->organization, 'gdpr');
        $job->handle($service);

        // Verify file was created
        $files = Storage::files('compliance_reports');
        $this->assertCount(1, $files);
        $this->assertStringContainsString('gdpr_report', $files[0]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_sends_email_to_recipients(): void
    {
        $recipients = ['admin@example.com', 'compliance@example.com'];

        $service = Mockery::mock(ComplianceReportService::class);
        $service->shouldReceive('generateSOC2Report')
            ->once()
            ->andReturn(['report_type' => 'SOC2']);

        $job = new GenerateComplianceReportJob($this->organization, 'soc2', $recipients);
        $job->handle($service);

        Mail::assertSent(\App\Mail\ComplianceReportGenerated::class, function ($mail) use ($recipients) {
            return $mail->hasTo($recipients);
        });
    }

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_throws_exception_for_invalid_report_type(): void
    {
        $service = Mockery::mock(ComplianceReportService::class);

        $job = new GenerateComplianceReportJob($this->organization, 'invalid_type');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid report type: invalid_type');

        $job->handle($service);
    }

    #[\PHPUnit\Framework\Attributes\Test]
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

        $files = Storage::files('compliance_reports');
        $this->assertCount(1, $files);

        $content = Storage::get($files[0]);
        $decoded = json_decode($content, true);

        $this->assertEquals('SOC2', $decoded['report_type']);
        $this->assertEquals(['test' => 'value'], $decoded['data']);
    }
}
