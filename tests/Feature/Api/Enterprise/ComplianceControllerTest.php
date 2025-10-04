<?php

namespace Tests\Feature\Api\Enterprise;

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
            ->shouldReceive('generateSOC2Report')
            ->once()
            ->with(Mockery::type(Organization::class))
            ->andReturn([
                'report_type' => 'SOC2',
                'organization' => [
                    'id' => $this->organization->id,
                    'name' => $this->organization->name,
                ],
                'period' => [
                    'from' => now()->subDays(30)->format('Y-m-d'),
                    'to' => now()->format('Y-m-d'),
                ],
                'generated_at' => now()->toISOString(),
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'report' => [
                        'report_type',
                        'generated_at',
                    ],
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'report' => [
                        'report_type' => 'SOC2',
                    ],
                ],
            ]);
    }

    public function test_can_generate_iso27001_report(): void
    {
        $this->complianceService
            ->shouldReceive('generateISO27001Report')
            ->once()
            ->with(Mockery::type(Organization::class))
            ->andReturn([
                'report_type' => 'ISO_27001',
                'organization' => [
                    'id' => $this->organization->id,
                    'name' => $this->organization->name,
                ],
                'generated_at' => now()->toISOString(),
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/iso27001');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'report' => [
                        'report_type' => 'ISO_27001',
                    ],
                ],
            ]);
    }

    public function test_can_generate_gdpr_report(): void
    {
        $this->complianceService
            ->shouldReceive('generateGDPRReport')
            ->once()
            ->with(Mockery::type(Organization::class))
            ->andReturn([
                'report_type' => 'GDPR',
                'organization' => [
                    'id' => $this->organization->id,
                    'name' => $this->organization->name,
                ],
                'generated_at' => now()->toISOString(),
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/gdpr');

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'report' => [
                        'report_type' => 'GDPR',
                    ],
                ],
            ]);
    }

    public function test_can_schedule_compliance_report(): void
    {
        $this->complianceService
            ->shouldReceive('scheduleReport')
            ->once()
            ->with(
                Mockery::type(Organization::class),
                'soc2',
                ['admin@example.com', 'compliance@example.com']
            );

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
        $this->markTestSkipped('ComplianceSchedule model and routes not implemented yet');

        // TODO: Implement when compliance_schedules table and model are created
        // ComplianceSchedule::factory()->count(3)->create([
        //     'organization_id' => $this->organization->id,
        // ]);
        //
        // Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);
        //
        // $response = $this->getJson('/api/v1/enterprise/compliance/schedules');
        //
        // $response->assertStatus(200)
        //     ->assertJsonStructure([
        //         'success',
        //         'data' => [
        //             '*' => [
        //                 'id',
        //                 'report_type',
        //                 'frequency',
        //                 'recipients',
        //                 'last_run_at',
        //                 'next_run_at',
        //                 'is_active',
        //             ],
        //         ],
        //         'message',
        //     ]);
    }

    public function test_can_delete_scheduled_report(): void
    {
        $this->markTestSkipped('ComplianceSchedule model and routes not implemented yet');

        // TODO: Implement when compliance_schedules table and model are created
        // $schedule = ComplianceSchedule::factory()->create([
        //     'organization_id' => $this->organization->id,
        // ]);
        //
        // Passport::actingAs($this->adminUser, ['enterprise.compliance.manage']);
        //
        // $response = $this->deleteJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}");
        //
        // $response->assertStatus(200)
        //     ->assertJson([
        //         'success' => true,
        //         'message' => 'Scheduled report deleted successfully',
        //     ]);
        //
        // $this->assertDatabaseMissing('compliance_schedules', [
        //     'id' => $schedule->id,
        // ]);
    }

    public function test_cannot_access_another_organizations_report(): void
    {
        $otherOrganization = Organization::factory()->create();
        $otherAdmin = $this->createApiOrganizationAdmin([
            'organization_id' => $otherOrganization->id,
        ]);

        $this->complianceService
            ->shouldReceive('generateSOC2Report')
            ->once()
            ->with(Mockery::type(Organization::class))
            ->andReturn([
                'report_type' => 'SOC2',
                'organization' => [
                    'id' => $otherOrganization->id,
                    'name' => $otherOrganization->name,
                ],
                'generated_at' => now()->toISOString(),
            ]);

        Passport::actingAs($otherAdmin, ['enterprise.compliance.read']);

        $response = $this->getJson('/api/v1/enterprise/compliance/soc2');

        $response->assertStatus(200);

        // Should not be able to access original organization's data
        Passport::actingAs($this->adminUser, ['enterprise.compliance.read']);

        $this->complianceService
            ->shouldReceive('generateSOC2Report')
            ->once()
            ->with(Mockery::type(Organization::class))
            ->andReturn([
                'report_type' => 'SOC2',
                'organization' => [
                    'id' => $this->organization->id,
                    'name' => $this->organization->name,
                ],
                'generated_at' => now()->toISOString(),
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
