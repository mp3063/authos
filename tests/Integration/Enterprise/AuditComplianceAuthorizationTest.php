<?php

namespace Tests\Integration\Enterprise;

use App\Models\AuditExport;
use App\Models\ComplianceReport;
use App\Models\ScheduledComplianceReport;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class AuditComplianceAuthorizationTest extends IntegrationTestCase
{
    #[Test]
    public function it_hides_another_organizations_exports_reports_and_schedules_from_an_owner_with_404(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $export = AuditExport::factory()->create();
        $report = ComplianceReport::factory()->completed()->create();
        $schedule = ScheduledComplianceReport::factory()->create();
        $this->actingAsApiUserWithToken($owner);

        $this->getJson("/api/v1/enterprise/audit/exports/{$export->id}/download")->assertNotFound();
        $this->getJson("/api/v1/enterprise/compliance/reports/{$report->id}/download")->assertNotFound();
        $this->patchJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}", ['is_active' => false])->assertNotFound();
        $this->deleteJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}")->assertNotFound();
        $this->assertModelExists($schedule);
    }

    #[Test]
    public function it_lets_an_organization_admin_read_but_not_generate_or_schedule(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $schedule = ScheduledComplianceReport::factory()->create(['organization_id' => $admin->organization_id]);
        $this->actingAsApiUserWithToken($admin);

        $this->getJson('/api/v1/enterprise/audit/exports')->assertOk();
        $this->getJson('/api/v1/enterprise/compliance/schedules')->assertOk();
        $this->getJson('/api/v1/enterprise/compliance/reports')->assertOk();
        $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'csv',
            'start_date' => now()->subDay()->toDateString(),
            'end_date' => now()->toDateString(),
        ])->assertForbidden();
        $this->getJson('/api/v1/enterprise/compliance/soc2')->assertForbidden();
        $this->postJson('/api/v1/enterprise/compliance/schedule', [
            'report_type' => 'soc2',
            'frequency' => 'monthly',
            'recipients' => ['a@example.com'],
        ])->assertForbidden();
        $this->patchJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}", ['is_active' => false])->assertForbidden();
        $this->deleteJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}")->assertForbidden();
        $this->assertModelExists($schedule);
    }

    #[Test]
    public function it_denies_a_plain_user_every_audit_and_compliance_read(): void
    {
        $member = $this->createApiUser();
        $this->actingAsApiUserWithToken($member);

        $this->getJson('/api/v1/enterprise/audit/exports')->assertForbidden();
        $this->getJson('/api/v1/enterprise/compliance/schedules')->assertForbidden();
        $this->getJson('/api/v1/enterprise/compliance/reports')->assertForbidden();
    }

    #[Test]
    public function it_lets_a_super_admin_without_an_organization_reach_any_organizations_compliance_records(): void
    {
        $super = $this->createApiSuperAdmin();
        $super->forceFill(['organization_id' => null])->save();
        $schedule = ScheduledComplianceReport::factory()->create();
        $report = ComplianceReport::factory()->create();
        $this->actingAsApiUserWithToken($super);

        $this->getJson('/api/v1/enterprise/compliance/schedules')->assertOk()->assertJsonCount(1, 'data.schedules');
        $this->getJson('/api/v1/enterprise/compliance/reports')->assertOk()->assertJsonCount(1, 'data.reports');
        $this->patchJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}", ['is_active' => false])->assertOk();
        $this->getJson("/api/v1/enterprise/compliance/reports/{$report->id}/download")->assertStatus(400);
        $this->deleteJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}")->assertOk();
    }
}
