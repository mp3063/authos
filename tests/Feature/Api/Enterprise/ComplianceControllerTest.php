<?php

namespace Tests\Feature\Api\Enterprise;

use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\User;
use App\Services\ComplianceReportService;
use Illuminate\Support\Facades\Mail;
use Laravel\Passport\Passport;
use Mockery;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class ComplianceControllerTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private ComplianceReportService $complianceService;

    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();

        $this->organization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'compliance_reports_enabled' => true,
                ],
            ],
        ]);

        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        $this->complianceService = Mockery::mock(ComplianceReportService::class);
        $this->app->instance(ComplianceReportService::class, $this->complianceService);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_can_generate_soc2_report(): void
    {
        $this->complianceService
            ->shouldReceive('generateReport')
            ->once()
            ->with($this->organization->id, 'soc2')
            ->andReturn([
                'type' => 'soc2',
                'generated_at' => now()->toIso8601String(),
                'sections' => [
                    'access_control' => [
                        'status' => 'compliant',
                        'metrics' => [
                            'mfa_enabled_users' => 85,
                            'total_users' => 100,
                        ],
                    ],
                    'audit_logging' => [
                        'status' => 'compliant',
                        'metrics' => [
                            'total_events' => 1500,
                            'retention_days' => 365,
                        ],
                    ],
                ],
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'report' => [
                        'type',
                        'generated_at',
                        'sections',
                    ],
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'report' => [
                        'type' => 'soc2',
                    ],
                ],
            ]);
    }

    public function test_can_generate_iso27001_report(): void
    {
        $this->complianceService
            ->shouldReceive('generateReport')
            ->once()
            ->with($this->organization->id, 'iso27001')
            ->andReturn([
                'type' => 'iso27001',
                'generated_at' => now()->toIso8601String(),
                'sections' => [
                    'information_security_policies' => [
                        'status' => 'compliant',
                    ],
                    'access_control' => [
                        'status' => 'compliant',
                    ],
                ],
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/iso27001');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'report' => [
                        'type' => 'iso27001',
                    ],
                ],
            ]);
    }

    public function test_can_generate_gdpr_report(): void
    {
        $this->complianceService
            ->shouldReceive('generateReport')
            ->once()
            ->with($this->organization->id, 'gdpr')
            ->andReturn([
                'type' => 'gdpr',
                'generated_at' => now()->toIso8601String(),
                'sections' => [
                    'data_protection' => [
                        'status' => 'compliant',
                        'metrics' => [
                            'encryption_enabled' => true,
                            'data_retention_policy' => true,
                        ],
                    ],
                    'user_rights' => [
                        'status' => 'compliant',
                        'metrics' => [
                            'export_requests_fulfilled' => 12,
                            'deletion_requests_fulfilled' => 5,
                        ],
                    ],
                ],
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/gdpr');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'report' => [
                        'type' => 'gdpr',
                    ],
                ],
            ]);
    }

    public function test_can_schedule_compliance_report(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.compliance.manage']);

        $response = $this->postJson('/api/v1/enterprise/compliance/schedule', [
            'report_type' => 'soc2',
            'frequency' => 'monthly',
            'recipients' => ['admin@example.com', 'compliance@example.com'],
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'schedule' => [
                        'report_type',
                        'frequency',
                        'recipients',
                        'next_run_at',
                    ],
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'schedule' => [
                        'report_type' => 'soc2',
                        'frequency' => 'monthly',
                    ],
                ],
            ]);

        $this->assertDatabaseHas('compliance_schedules', [
            'organization_id' => $this->organization->id,
            'report_type' => 'soc2',
            'frequency' => 'monthly',
        ]);
    }

    public function test_validates_schedule_parameters(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.compliance.manage']);

        $response = $this->postJson('/api/v1/enterprise/compliance/schedule', [
            'report_type' => 'invalid',
            'frequency' => 'never',
            'recipients' => ['not-an-email'],
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['report_type', 'frequency', 'recipients.0']);
    }

    public function test_can_list_scheduled_reports(): void
    {
        ComplianceReport::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/schedules');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'report_type',
                        'frequency',
                        'recipients',
                        'last_run_at',
                        'next_run_at',
                        'is_active',
                    ],
                ],
                'message',
            ]);
    }

    public function test_can_delete_scheduled_report(): void
    {
        $schedule = ComplianceReport::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.manage']);

        $response = $this->deleteJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}");

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Scheduled report deleted successfully',
            ]);

        $this->assertDatabaseMissing('compliance_schedules', [
            'id' => $schedule->id,
        ]);
    }

    public function test_cannot_access_another_organizations_report(): void
    {
        $otherOrganization = Organization::factory()->create();
        $otherAdmin = $this->createApiOrganizationAdmin([
            'organization_id' => $otherOrganization->id,
        ]);

        $this->complianceService
            ->shouldReceive('generateReport')
            ->once()
            ->with($otherOrganization->id, 'soc2')
            ->andReturn([
                'type' => 'soc2',
                'generated_at' => now()->toIso8601String(),
            ]);

        Passport::actingAs($otherAdmin, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');

        $response->assertStatus(200);

        // Should not be able to access original organization's data
        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $this->complianceService
            ->shouldReceive('generateReport')
            ->once()
            ->with($this->organization->id, 'soc2')
            ->andReturn([
                'type' => 'soc2',
                'generated_at' => now()->toIso8601String(),
            ]);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');
        $response->assertStatus(200);
    }

    public function test_requires_compliance_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');

        $response->assertStatus(403);
    }

    public function test_compliance_reports_disabled_for_organization_returns_error(): void
    {
        $this->organization->update([
            'settings' => [
                'enterprise_features' => [
                    'compliance_reports_enabled' => false,
                ],
            ],
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');

        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'error' => 'feature_disabled',
            ]);
    }
}
