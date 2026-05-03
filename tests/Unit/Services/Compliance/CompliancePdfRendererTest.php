<?php

namespace Tests\Unit\Services\Compliance;

use App\Models\Organization;
use App\Services\Compliance\CompliancePdfRenderer;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class CompliancePdfRendererTest extends TestCase
{
    private CompliancePdfRenderer $renderer;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake('local');
        Storage::fake('public');
        $this->renderer = app(CompliancePdfRenderer::class);
        $this->organization = Organization::factory()->create();
    }

    #[Test]
    public function it_throws_for_unknown_report_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->renderer->render('pci', $this->stubReport(), $this->organization);
    }

    #[Test]
    public function it_renders_soc2_pdf_to_local_disk(): void
    {
        $relativePath = $this->renderer->render('soc2', $this->stubReport(), $this->organization);

        $this->assertStringStartsWith("compliance_reports/{$this->organization->id}/soc2_", $relativePath);
        $this->assertStringEndsWith('.pdf', $relativePath);
        $this->assertTrue(Storage::disk('local')->exists($relativePath));

        $bytes = Storage::disk('local')->get($relativePath);
        $this->assertNotNull($bytes);
        $this->assertStringStartsWith('%PDF-', $bytes, 'File should be a valid PDF');
        $this->assertGreaterThan(1024, strlen($bytes), 'PDF should not be tiny/empty');
    }

    #[Test]
    public function it_renders_iso27001_and_gdpr_templates(): void
    {
        $iso = $this->renderer->render('iso27001', $this->stubReport('ISO_27001'), $this->organization);
        $gdpr = $this->renderer->render('gdpr', $this->stubReport('GDPR'), $this->organization);

        foreach ([$iso, $gdpr] as $path) {
            $bytes = Storage::disk('local')->get($path);
            $this->assertStringStartsWith('%PDF-', (string) $bytes);
        }
    }

    #[Test]
    public function it_skips_logo_when_branding_logo_path_missing_on_disk(): void
    {
        // No file is created on the public disk, so resolveLogoPath() returns null
        // and the template falls back to the no-logo branch.
        $relativePath = $this->renderer->render('soc2', $this->stubReport(), $this->organization);
        $this->assertStringStartsWith('%PDF-', (string) Storage::disk('local')->get($relativePath));
    }

    private function stubReport(string $type = 'SOC2'): array
    {
        return [
            'report_type' => $type,
            'organization' => ['id' => $this->organization->id, 'name' => $this->organization->name],
            'period' => ['from' => '2026-04-03', 'to' => '2026-05-03', 'days' => 31],
            'access_controls' => [
                'total_users' => 50,
                'active_users' => 47,
                'role_based_access' => true,
                'applications_count' => 4,
            ],
            'authentication' => [
                'total_attempts' => 1234,
                'successful_logins' => 1100,
                'failed_logins' => 134,
                'unique_users' => 45,
                'average_daily_logins' => 39.8,
            ],
            'mfa_adoption' => [
                'total_users' => 50,
                'mfa_enabled_users' => 38,
                'adoption_rate_percentage' => 76.0,
                'compliance_status' => 'non_compliant',
            ],
            'security_incidents' => [
                'total_incidents' => 134,
                'failed_login_attempts' => 134,
                'suspicious_activities' => 0,
                'incident_details' => [
                    ['event' => 'login_failed', 'ip_address' => '203.0.113.5', 'created_at' => '2026-05-01T10:15:00Z'],
                ],
            ],
            'incident_management' => [
                'total_incidents' => 4,
                'resolved_incidents' => 3,
                'open_critical_count' => 0,
                'response_time_avg_minutes' => 42.0,
                'resolution_rate_percentage' => 75.0,
            ],
            'access_management' => ['role_count' => 5, 'permission_count' => 30, 'custom_roles' => 1],
            'user_provisioning' => ['new_users_in_period' => 2, 'automated_provisioning' => false, 'deprovisioning_process' => 'manual'],
            'audit_trail' => ['total_audit_records' => 9999, 'records_in_period' => 1234, 'retention_period_days' => 365, 'auto_pruning_enabled' => false, 'last_pruned_at' => null],
            'data_subjects_count' => 50,
            'data_access_logs' => ['total_access_logs' => 1234, 'data_export_requests' => 0],
            'retention_policy' => ['policy_defined' => true, 'retention_period_days' => 365, 'auto_deletion' => false, 'last_enforced_at' => null],
            'consent_tracking' => [
                'total_consents' => 47,
                'total_consents_active' => 47,
                'total_consents_withdrawn' => 3,
                'consent_coverage_percentage' => 94.0,
                'data_subject_requests' => ['access' => 1, 'rectification' => 0, 'deletion' => 0, 'portability' => 0, 'restriction' => 0],
            ],
            'generated_at' => now()->toISOString(),
        ];
    }
}
