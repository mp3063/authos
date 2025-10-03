<?php

namespace Tests\Unit\Services;

use App\Jobs\GenerateComplianceReportJob;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\ComplianceReportService;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class ComplianceReportServiceTest extends TestCase
{
    private ComplianceReportService $service;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new ComplianceReportService;
        $this->organization = Organization::factory()->create();
    }

    public function test_schedule_report_dispatches_job(): void
    {
        Queue::fake();

        $recipients = ['admin@example.com', 'compliance@example.com'];

        $this->service->scheduleReport($this->organization, 'soc2', $recipients);

        Queue::assertPushed(GenerateComplianceReportJob::class, function ($job) {
            return $job->reportType === 'soc2';
        });
    }

    public function test_generate_soc2_report_returns_complete_structure(): void
    {
        // Create test data
        User::factory()->count(10)->withMfa()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Create authentication logs linked to users in the organization
        $users = User::where('organization_id', $this->organization->id)->get();
        foreach ($users as $user) {
            AuthenticationLog::factory()->count(5)->create([
                'user_id' => $user->id,
                'success' => true,
            ]);
        }

        $report = $this->service->generateSOC2Report($this->organization);

        $this->assertIsArray($report);
        $this->assertEquals('SOC2', $report['report_type']);
        $this->assertArrayHasKey('organization', $report);
        $this->assertArrayHasKey('period', $report);
        $this->assertArrayHasKey('access_controls', $report);
        $this->assertArrayHasKey('authentication', $report);
        $this->assertArrayHasKey('mfa_adoption', $report);
        $this->assertArrayHasKey('security_incidents', $report);
        $this->assertArrayHasKey('generated_at', $report);
    }

    public function test_generate_soc2_report_calculates_access_controls(): void
    {
        User::factory()->count(15)->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
            'is_active' => false,
        ]);

        $report = $this->service->generateSOC2Report($this->organization);

        $this->assertEquals(20, $report['access_controls']['total_users']);
        $this->assertEquals(15, $report['access_controls']['active_users']);
    }

    public function test_generate_soc2_report_calculates_mfa_adoption(): void
    {
        User::factory()->count(18)->withMfa()->create([
            'organization_id' => $this->organization->id,
        ]);

        User::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
        ]);

        $report = $this->service->generateSOC2Report($this->organization);

        $this->assertEquals(20, $report['mfa_adoption']['total_users']);
        $this->assertEquals(18, $report['mfa_adoption']['mfa_enabled_users']);
        $this->assertEquals(90.0, $report['mfa_adoption']['adoption_rate_percentage']);
        $this->assertEquals('compliant', $report['mfa_adoption']['compliance_status']);
    }

    public function test_generate_soc2_report_identifies_non_compliant_mfa(): void
    {
        User::factory()->count(8)->withMfa()->create([
            'organization_id' => $this->organization->id,
        ]);

        User::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
        ]);

        $report = $this->service->generateSOC2Report($this->organization);

        $this->assertEquals(80.0, $report['mfa_adoption']['adoption_rate_percentage']);
        $this->assertEquals('non_compliant', $report['mfa_adoption']['compliance_status']);
    }

    public function test_generate_iso27001_report_returns_complete_structure(): void
    {
        $report = $this->service->generateISO27001Report($this->organization);

        $this->assertIsArray($report);
        $this->assertEquals('ISO_27001', $report['report_type']);
        $this->assertArrayHasKey('organization', $report);
        $this->assertArrayHasKey('access_management', $report);
        $this->assertArrayHasKey('incident_management', $report);
        $this->assertArrayHasKey('user_provisioning', $report);
        $this->assertArrayHasKey('audit_trail', $report);
        $this->assertArrayHasKey('generated_at', $report);
    }

    public function test_generate_gdpr_report_returns_complete_structure(): void
    {
        User::factory()->count(100)->create([
            'organization_id' => $this->organization->id,
        ]);

        $report = $this->service->generateGDPRReport($this->organization);

        $this->assertIsArray($report);
        $this->assertEquals('GDPR', $report['report_type']);
        $this->assertArrayHasKey('organization', $report);
        $this->assertArrayHasKey('data_subjects_count', $report);
        $this->assertArrayHasKey('data_access_logs', $report);
        $this->assertArrayHasKey('retention_policy', $report);
        $this->assertArrayHasKey('consent_tracking', $report);
        $this->assertArrayHasKey('generated_at', $report);
        $this->assertEquals(100, $report['data_subjects_count']);
    }

    public function test_generate_soc2_report_includes_authentication_metrics(): void
    {
        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        AuthenticationLog::factory()->count(30)->create([
            'user_id' => $user->id,
            'success' => true,
            'created_at' => now()->subDays(15),
        ]);

        AuthenticationLog::factory()->count(5)->create([
            'user_id' => $user->id,
            'success' => false,
            'created_at' => now()->subDays(10),
        ]);

        $report = $this->service->generateSOC2Report($this->organization);

        $this->assertEquals(35, $report['authentication']['total_attempts']);
        $this->assertEquals(30, $report['authentication']['successful_logins']);
        $this->assertEquals(5, $report['authentication']['failed_logins']);
    }

    public function test_generate_soc2_report_tracks_security_incidents(): void
    {
        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        AuthenticationLog::factory()->count(8)->create([
            'user_id' => $user->id,
            'success' => false,
            'event' => 'login_failed',
            'created_at' => now()->subDays(15),
        ]);

        AuthenticationLog::factory()->count(2)->create([
            'user_id' => $user->id,
            'success' => false,
            'event' => 'suspicious_activity',
            'created_at' => now()->subDays(10),
        ]);

        $report = $this->service->generateSOC2Report($this->organization);

        $this->assertEquals(10, $report['security_incidents']['total_incidents']);
        $this->assertEquals(8, $report['security_incidents']['failed_login_attempts']);
        $this->assertEquals(2, $report['security_incidents']['suspicious_activities']);
        $this->assertIsArray($report['security_incidents']['incident_details']);
        $this->assertLessThanOrEqual(10, count($report['security_incidents']['incident_details']));
    }

    public function test_generate_gdpr_report_includes_retention_policy(): void
    {
        $report = $this->service->generateGDPRReport($this->organization);

        $this->assertArrayHasKey('retention_policy', $report);
        $this->assertTrue($report['retention_policy']['policy_defined']);
        $this->assertEquals('365 days', $report['retention_policy']['retention_period']);
    }

    public function test_generate_gdpr_report_includes_consent_metrics(): void
    {
        User::factory()->count(50)->create([
            'organization_id' => $this->organization->id,
        ]);

        $report = $this->service->generateGDPRReport($this->organization);

        $this->assertEquals(50, $report['consent_tracking']['total_consents']);
        $this->assertEquals('available', $report['consent_tracking']['consent_withdrawal_process']);
    }
}
