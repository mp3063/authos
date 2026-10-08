<?php

namespace Tests\Integration\Enterprise;

use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class EnterprisePermissionGuardsTest extends IntegrationTestCase
{
    #[Test]
    public function it_forbids_a_plain_user_with_a_star_token_from_exporting_audit_logs_with_403(): void
    {
        $user = $this->createApiUser();
        $this->actingAsApiUserWithToken($user, ['*']);

        $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'csv',
            'start_date' => now()->subDays(7)->toDateString(),
            'end_date' => now()->toDateString(),
        ])->assertForbidden();

        $this->getJson('/api/v1/enterprise/audit/exports')->assertForbidden();
    }

    #[Test]
    public function it_forbids_a_plain_user_with_a_star_token_from_generating_a_compliance_report_with_403(): void
    {
        $user = $this->createApiUser();
        $this->actingAsApiUserWithToken($user, ['*']);

        $this->getJson('/api/v1/enterprise/compliance/soc2')->assertForbidden();
        $this->postJson('/api/v1/enterprise/compliance/schedule', [
            'report_type' => 'soc2',
            'frequency' => 'weekly',
            'recipients' => ['a@example.com'],
        ])->assertForbidden();
        $this->getJson('/api/v1/enterprise/compliance/reports')->assertForbidden();
        $this->getJson('/api/v1/enterprise/compliance/schedules')->assertForbidden();
    }

    #[Test]
    public function it_forbids_a_plain_user_with_a_star_token_from_writing_branding_with_403(): void
    {
        $user = $this->createApiUser();
        $this->actingAsApiUserWithToken($user, ['*']);

        $this->putJson("/api/v1/enterprise/organizations/{$user->organization_id}/branding", [
            'primary_color' => '#112233',
        ])->assertForbidden();
    }

    #[Test]
    public function it_forbids_a_plain_user_with_a_star_token_from_exporting_security_logs_with_403(): void
    {
        $user = $this->createApiUser();
        $this->actingAsApiUserWithToken($user, ['*']);

        $this->postJson("/api/v1/organizations/{$user->organization_id}/export", [
            'data_type' => 'security_logs',
        ])->assertForbidden();
        $this->postJson("/api/v1/organizations/{$user->organization_id}/export", [
            'data_type' => 'users',
        ])->assertForbidden();
        $this->getJson("/api/v1/organizations/{$user->organization_id}/metrics/security")->assertForbidden();
    }

    #[Test]
    public function it_allows_an_organization_admin_with_a_star_token_to_export_audit_logs(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $this->actingAsApiUserWithToken($admin, ['*']);

        $this->getJson('/api/v1/enterprise/audit/exports')->assertOk();
    }
}
