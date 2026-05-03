<?php

namespace Tests\Unit\Services\ComplianceReportService;

use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Services\ComplianceReportService;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class IncidentMetricsTest extends TestCase
{
    private ComplianceReportService $service;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = app(ComplianceReportService::class);
        $this->organization = Organization::factory()->create();
    }

    #[Test]
    public function returns_null_metrics_when_no_incidents(): void
    {
        $report = $this->service->generateISO27001Report($this->organization);

        $this->assertSame(0, $report['incident_management']['total_incidents']);
        $this->assertSame(0, $report['incident_management']['resolved_incidents']);
        $this->assertNull($report['incident_management']['response_time_avg_minutes']);
        $this->assertNull($report['incident_management']['resolution_rate_percentage']);
    }

    #[Test]
    public function counts_resolved_and_open_incidents_in_period(): void
    {
        $within = CarbonImmutable::now()->subDays(5);
        $beforeWindow = CarbonImmutable::now()->subDays(60);

        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => $within,
            'resolved_at' => $within->addHour(),
            'status' => 'resolved',
        ]);
        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => $within,
            'resolved_at' => $within->addMinutes(30),
            'status' => 'resolved',
        ]);
        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => $within,
            'resolved_at' => null,
            'status' => 'open',
            'severity' => 'critical',
        ]);
        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => $within,
            'resolved_at' => null,
            'status' => 'open',
            'severity' => 'low',
        ]);

        // Outside the 30-day default window - must not count
        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => $beforeWindow,
            'resolved_at' => $beforeWindow->addHour(),
            'status' => 'resolved',
        ]);

        $metrics = $this->service->generateISO27001Report($this->organization)['incident_management'];

        $this->assertSame(4, $metrics['total_incidents']);
        $this->assertSame(2, $metrics['resolved_incidents']);
        $this->assertSame(1, $metrics['open_critical_count']);
        // 60min + 30min = 90min total / 2 incidents = 45min avg
        $this->assertSame(45.0, $metrics['response_time_avg_minutes']);
        // 2 resolved / 4 total = 50%
        $this->assertSame(50.0, $metrics['resolution_rate_percentage']);
    }

    #[Test]
    public function isolates_metrics_per_organization(): void
    {
        $other = Organization::factory()->create();

        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => now()->subHour(),
            'resolved_at' => now(),
            'status' => 'resolved',
        ]);
        SecurityIncident::factory()->forOrganization($other)->count(5)->create([
            'detected_at' => now()->subHour(),
        ]);

        $mine = $this->service->generateISO27001Report($this->organization)['incident_management'];
        $theirs = $this->service->generateISO27001Report($other)['incident_management'];

        $this->assertSame(1, $mine['total_incidents']);
        $this->assertSame(5, $theirs['total_incidents']);
    }

    #[Test]
    public function honours_custom_period_window(): void
    {
        $longAgo = CarbonImmutable::create(2026, 1, 1, 12);

        SecurityIncident::factory()->forOrganization($this->organization)->create([
            'detected_at' => $longAgo,
            'resolved_at' => $longAgo->addHours(2),
            'status' => 'resolved',
        ]);

        $defaultWindow = $this->service->generateISO27001Report($this->organization)['incident_management'];
        $customWindow = $this->service->generateISO27001Report(
            $this->organization,
            $longAgo->subDay(),
            $longAgo->addDay(),
        )['incident_management'];

        $this->assertSame(0, $defaultWindow['total_incidents']);
        $this->assertSame(1, $customWindow['total_incidents']);
        $this->assertSame(120.0, $customWindow['response_time_avg_minutes']);
    }

    #[Test]
    public function deprovisioning_process_reflects_ldap_configuration(): void
    {
        $report = $this->service->generateISO27001Report($this->organization);
        $this->assertSame('manual', $report['user_provisioning']['deprovisioning_process']);
        $this->assertFalse($report['user_provisioning']['automated_provisioning']);
    }

    #[Test]
    public function retention_policy_reads_from_organization_settings(): void
    {
        $this->organization->forceFill([
            'settings' => [
                'security' => [
                    'retention_period_days' => 90,
                    'auto_pruning_enabled' => true,
                    'last_pruned_at' => '2026-04-30T03:00:00Z',
                ],
            ],
        ])->save();

        $report = $this->service->generateGDPRReport($this->organization);
        $policy = $report['retention_policy'];

        $this->assertTrue($policy['policy_defined']);
        $this->assertSame(90, $policy['retention_period_days']);
        $this->assertTrue($policy['auto_deletion']);
        $this->assertSame('2026-04-30T03:00:00Z', $policy['last_enforced_at']);
    }

    #[Test]
    public function retention_policy_falls_back_to_config_default_when_unset(): void
    {
        config(['compliance.default_retention_days' => 365]);

        $report = $this->service->generateGDPRReport($this->organization);
        $policy = $report['retention_policy'];

        $this->assertFalse($policy['policy_defined']);
        $this->assertSame(365, $policy['retention_period_days']);
        $this->assertFalse($policy['auto_deletion']);
        $this->assertNull($policy['last_enforced_at']);
    }
}
