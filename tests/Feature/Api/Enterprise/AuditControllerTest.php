<?php

namespace Tests\Feature\Api\Enterprise;

use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\AuditExportService;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Mockery;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class AuditControllerTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private AuditExportService $auditService;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        $this->organization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'audit_exports_enabled' => true,
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

        // Create sample authentication logs
        AuthenticationLog::factory()->count(10)->create([
            'metadata' => [
                'organization_id' => $this->organization->id,
            ],
        ]);

        $this->auditService = Mockery::mock(AuditExportService::class);
        $this->app->instance(AuditExportService::class, $this->auditService);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_can_create_audit_export(): void
    {
        $this->auditService
            ->shouldReceive('createExport')
            ->once()
            ->with(
                $this->organization->id,
                Mockery::type('array')
            )
            ->andReturn([
                'id' => 1,
                'format' => 'csv',
                'status' => 'pending',
                'file_path' => null,
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.audit.manage']);

        $response = $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'csv',
            'start_date' => now()->subDays(30)->toDateString(),
            'end_date' => now()->toDateString(),
            'event_types' => ['login', 'logout'],
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'export' => [
                        'id',
                        'format',
                        'status',
                    ],
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'export' => [
                        'status' => 'pending',
                    ],
                ],
            ]);
    }

    public function test_can_list_exports(): void
    {
        AuditExport::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.audit.read']);

        $response = $this->getJson('/api/v1/enterprise/audit/exports');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'format',
                        'status',
                        'file_path',
                        'filters',
                        'created_at',
                        'completed_at',
                    ],
                ],
                'message',
            ])
            ->assertJsonCount(3, 'data');
    }

    public function test_can_download_export(): void
    {
        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'status' => 'completed',
            'file_path' => 'exports/audit-export-123.csv',
        ]);

        Storage::disk('local')->put($export->file_path, 'test,data,content');

        Passport::actingAs($this->adminUser, ['enterprise.audit.read']);

        $response = $this->getJson("/api/v1/enterprise/audit/exports/{$export->id}/download");

        $response->assertStatus(200)
            ->assertHeader('Content-Type', 'text/csv')
            ->assertHeader('Content-Disposition', 'attachment; filename="audit-export-123.csv"');
    }

    public function test_validates_export_parameters(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.audit.manage']);

        $response = $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'invalid',
            'start_date' => 'not-a-date',
            'end_date' => 'also-not-a-date',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['format', 'start_date', 'end_date']);
    }

    public function test_filters_export_by_date_range(): void
    {
        $this->auditService
            ->shouldReceive('createExport')
            ->once()
            ->with(
                $this->organization->id,
                Mockery::on(function ($filters) {
                    return isset($filters['start_date']) &&
                        isset($filters['end_date']) &&
                        $filters['start_date'] === '2024-01-01' &&
                        $filters['end_date'] === '2024-01-31';
                })
            )
            ->andReturn([
                'id' => 1,
                'format' => 'json',
                'status' => 'pending',
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.audit.manage']);

        $response = $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'json',
            'start_date' => '2024-01-01',
            'end_date' => '2024-01-31',
        ]);

        $response->assertStatus(201);
    }

    public function test_supports_multiple_formats(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.audit.manage']);

        foreach (['csv', 'json', 'xlsx'] as $format) {
            $this->auditService
                ->shouldReceive('createExport')
                ->once()
                ->andReturn([
                    'id' => 1,
                    'format' => $format,
                    'status' => 'pending',
                ]);

            $response = $this->postJson('/api/v1/enterprise/audit/export', [
                'format' => $format,
                'start_date' => now()->subDays(7)->toDateString(),
                'end_date' => now()->toDateString(),
            ]);

            $response->assertStatus(201)
                ->assertJson([
                    'success' => true,
                ]);
        }
    }

    public function test_cannot_download_another_organizations_export(): void
    {
        $otherOrganization = Organization::factory()->create();
        $export = AuditExport::factory()->create([
            'organization_id' => $otherOrganization->id,
            'status' => 'completed',
            'file_path' => 'exports/other-export.csv',
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.audit.read']);

        $response = $this->getJson("/api/v1/enterprise/audit/exports/{$export->id}/download");

        $response->assertStatus(404);
    }

    public function test_cannot_download_pending_export(): void
    {
        $export = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'status' => 'pending',
            'file_path' => null,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.audit.read']);

        $response = $this->getJson("/api/v1/enterprise/audit/exports/{$export->id}/download");

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'error' => 'export_not_ready',
            ]);
    }

    public function test_requires_audit_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $response = $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'csv',
            'start_date' => now()->subDays(7)->toDateString(),
            'end_date' => now()->toDateString(),
        ]);

        $response->assertStatus(403);
    }

    public function test_audit_exports_disabled_for_organization_returns_error(): void
    {
        $this->organization->update([
            'settings' => [
                'enterprise_features' => [
                    'audit_exports_enabled' => false,
                ],
            ],
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.audit.manage']);

        $response = $this->postJson('/api/v1/enterprise/audit/export', [
            'format' => 'csv',
            'start_date' => now()->subDays(7)->toDateString(),
            'end_date' => now()->toDateString(),
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'error' => 'feature_disabled',
            ]);
    }
}
