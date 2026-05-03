<?php

namespace Tests\Unit\Models;

use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\User;
use Carbon\Carbon;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ComplianceReportTest extends TestCase
{
    #[Test]
    public function it_casts_dates_and_summary_correctly(): void
    {
        $report = ComplianceReport::factory()->completed()->create([
            'period_start' => '2026-01-01',
            'period_end' => '2026-01-31',
            'summary' => ['total_users' => 42, 'mfa_adoption_rate' => 73.5],
        ]);

        $report->refresh();

        $this->assertInstanceOf(Carbon::class, $report->period_start);
        $this->assertInstanceOf(Carbon::class, $report->period_end);
        $this->assertInstanceOf(Carbon::class, $report->generated_at);
        $this->assertInstanceOf(Carbon::class, $report->expires_at);
        $this->assertSame('2026-01-01', $report->period_start->toDateString());
        $this->assertIsArray($report->summary);
        $this->assertSame(42, $report->summary['total_users']);
    }

    #[Test]
    public function it_has_organization_relation(): void
    {
        $org = Organization::factory()->create();
        $report = ComplianceReport::factory()->create(['organization_id' => $org->id]);

        $this->assertTrue($report->organization->is($org));
    }

    #[Test]
    public function it_has_generated_by_user_relation(): void
    {
        $user = User::factory()->create();
        $report = ComplianceReport::factory()->create(['generated_by_user_id' => $user->id]);

        $this->assertTrue($report->generatedBy->is($user));
    }

    #[Test]
    public function it_has_schedule_relation(): void
    {
        $schedule = ScheduledComplianceReport::factory()->create();
        $report = ComplianceReport::factory()->create(['scheduled_report_id' => $schedule->id]);

        $this->assertTrue($report->schedule->is($schedule));
    }

    #[Test]
    public function is_completed_reflects_status(): void
    {
        $generating = ComplianceReport::factory()->create(['status' => ComplianceReport::STATUS_GENERATING]);
        $completed = ComplianceReport::factory()->completed()->create();
        $failed = ComplianceReport::factory()->failed()->create();

        $this->assertFalse($generating->isCompleted());
        $this->assertTrue($completed->isCompleted());
        $this->assertFalse($failed->isCompleted());
    }

    #[Test]
    public function is_expired_handles_null_and_past_dates(): void
    {
        $noExpiry = ComplianceReport::factory()->create(['expires_at' => null]);
        $current = ComplianceReport::factory()->completed()->create(['expires_at' => now()->addDay()]);
        $past = ComplianceReport::factory()->expired()->create();

        $this->assertFalse($noExpiry->isExpired());
        $this->assertFalse($current->isExpired());
        $this->assertTrue($past->isExpired());
    }

    #[Test]
    public function download_urls_are_null_when_not_completed(): void
    {
        $report = ComplianceReport::factory()->create([
            'status' => ComplianceReport::STATUS_GENERATING,
            'file_path_pdf' => 'compliance_reports/1/test.pdf',
            'file_path_json' => 'compliance_reports/1/test.json',
        ]);

        $this->assertNull($report->pdfDownloadUrl());
        $this->assertNull($report->jsonDownloadUrl());
    }

    #[Test]
    public function download_urls_are_null_when_file_path_missing(): void
    {
        $report = ComplianceReport::factory()->create([
            'status' => ComplianceReport::STATUS_COMPLETED,
            'file_path_pdf' => null,
            'file_path_json' => null,
        ]);

        $this->assertNull($report->pdfDownloadUrl());
        $this->assertNull($report->jsonDownloadUrl());
    }

    #[Test]
    public function for_organization_scope_filters_correctly(): void
    {
        $orgA = Organization::factory()->create();
        $orgB = Organization::factory()->create();
        ComplianceReport::factory()->count(2)->create(['organization_id' => $orgA->id]);
        ComplianceReport::factory()->count(3)->create(['organization_id' => $orgB->id]);

        $this->assertSame(2, ComplianceReport::query()->forOrganization($orgA->id)->count());
        $this->assertSame(3, ComplianceReport::query()->forOrganization($orgB->id)->count());
    }

    #[Test]
    public function completed_scope_filters_by_status(): void
    {
        ComplianceReport::factory()->count(2)->completed()->create();
        ComplianceReport::factory()->failed()->create();
        ComplianceReport::factory()->create();

        $this->assertSame(2, ComplianceReport::query()->completed()->count());
    }
}
