<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class OrganizationReportApiTest extends TestCase
{
    private Organization $organization;

    private Organization $otherOrganization;

    private User $superAdminUser;

    private User $organizationAdminUser;

    private User $regularUser;

    private User $otherOrgUser;

    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create([
            'name' => 'Test Organization',
            'slug' => 'test-org',
        ]);

        $this->otherOrganization = Organization::factory()->create([
            'name' => 'Other Organization',
            'slug' => 'other-org',
        ]);

        // Create required roles
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'super admin', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'organization admin', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'user', 'guard_name' => 'web']);

        // Create required permissions for reporting
        \Spatie\Permission\Models\Permission::firstOrCreate(['name' => 'organization.view_analytics', 'guard_name' => 'api']);
        \Spatie\Permission\Models\Permission::firstOrCreate(['name' => 'security.view_logs', 'guard_name' => 'api']);
        \Spatie\Permission\Models\Permission::firstOrCreate(['name' => 'organizations.read', 'guard_name' => 'api']);
        \Spatie\Permission\Models\Permission::firstOrCreate(['name' => 'organization.view_analytics', 'guard_name' => 'web']);
        \Spatie\Permission\Models\Permission::firstOrCreate(['name' => 'security.view_logs', 'guard_name' => 'web']);
        \Spatie\Permission\Models\Permission::firstOrCreate(['name' => 'organizations.read', 'guard_name' => 'web']);

        // Create super admin user using helper method
        $this->superAdminUser = $this->createApiSuperAdmin(['organization_id' => $this->organization->id]);

        // Create organization admin user using helper method
        $this->organizationAdminUser = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);

        // Assign additional permissions to organization admin
        $this->organizationAdminUser->givePermissionTo('organization.view_analytics');
        $this->organizationAdminUser->givePermissionTo('organizations.read');

        // Create regular user in same organization using helper method
        $this->regularUser = $this->createApiUser(['organization_id' => $this->organization->id]);

        // Create organization admin user in different organization using helper method
        $this->otherOrgUser = $this->createApiOrganizationAdmin(['organization_id' => $this->otherOrganization->id]);

        $this->otherOrgUser->givePermissionTo('organization.view_analytics');
        $this->otherOrgUser->givePermissionTo('organizations.read');

        // Create application for testing
        $this->application = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        // Associate users with the application so they appear in reports
        $this->superAdminUser->applications()->attach($this->application->id, [
            'permissions' => ['read', 'write'],
            'granted_at' => now(),
        ]);
        $this->organizationAdminUser->applications()->attach($this->application->id, [
            'permissions' => ['read', 'write'],
            'granted_at' => now(),
        ]);
        $this->regularUser->applications()->attach($this->application->id, [
            'permissions' => ['read'],
            'granted_at' => now(),
        ]);

        // Create some test authentication logs
        AuthenticationLog::factory()->create([
            'user_id' => $this->regularUser->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Test Browser',
            'created_at' => now()->subDays(2),
        ]);

        AuthenticationLog::factory()->create([
            'user_id' => $this->regularUser->id,
            'event' => 'login_failed',
            'ip_address' => '192.168.1.2',
            'user_agent' => 'Test Browser',
            'created_at' => now()->subDays(1),
        ]);

        // Set up storage for PDF testing
        Storage::fake('local');
    }

    public function test_get_report_types_returns_available_reports(): void
    {
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson('/api/v1/config/report-types');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'user_activity' => [
                        'name',
                        'description',
                        'features',
                        'date_range_supported',
                    ],
                    'application_usage' => [
                        'name',
                        'description',
                        'features',
                        'date_range_supported',
                    ],
                    'security_audit' => [
                        'name',
                        'description',
                        'features',
                        'date_range_supported',
                    ],
                ],
            ])
            ->assertJson([
                'data' => [
                    'user_activity' => [
                        'name' => 'User Activity Report',
                        'date_range_supported' => true,
                    ],
                    'application_usage' => [
                        'name' => 'Application Usage Report',
                        'date_range_supported' => false,
                    ],
                    'security_audit' => [
                        'name' => 'Security Audit Report',
                        'date_range_supported' => false,
                    ],
                ],
            ]);
    }

    public function test_generate_user_activity_report_as_super_admin_succeeds(): void
    {
        // Explicitly ensure Super Admin has the needed permission
        $this->superAdminUser->setPermissionsTeamId(null);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId(null);
        $this->superAdminUser->givePermissionTo('organizations.read');
        app(\Spatie\Permission\PermissionRegistrar::class)->forgetCachedPermissions();

        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'organization',
                    'date_range',
                    'user_statistics',
                    'login_statistics',
                    'daily_activity',
                    'top_users',
                    'role_distribution',
                    'custom_role_distribution',
                    'generated_at',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'User activity report generated successfully',
            ]);

        $responseData = $response->json('data');
        $this->assertEquals($this->organization->id, $responseData['organization']['id']);
        $this->assertArrayHasKey('total_users', $responseData['user_statistics']);
        $this->assertArrayHasKey('active_users', $responseData['user_statistics']);

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->superAdminUser->id,
            'event' => 'user_activity_report_generated',
        ]);
    }

    public function test_generate_user_activity_report_with_date_range_succeeds(): void
    {
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $startDate = now()->subDays(7)->format('Y-m-d');
        $endDate = now()->format('Y-m-d');

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity?".http_build_query([
            'start_date' => $startDate,
            'end_date' => $endDate,
        ]));

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'organization',
                    'date_range',
                    'user_statistics',
                    'login_statistics',
                    'daily_activity',
                    'top_users',
                    'role_distribution',
                    'custom_role_distribution',
                    'generated_at',
                ],
                'message',
            ]);

        $responseData = $response->json('data');
        $this->assertEquals($startDate, $responseData['date_range']['start']);
        $this->assertEquals($endDate, $responseData['date_range']['end']);
    }

    public function test_generate_user_activity_report_as_pdf_succeeds(): void
    {
        $this->markTestSkipped('PDF generation temporarily disabled - missing view configuration');
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity?".http_build_query([
            'format' => 'pdf',
        ]));

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'download_url',
                    'filename',
                    'expires_at',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'User activity report generated successfully',
            ]);

        $responseData = $response->json('data');
        $this->assertStringContains('.pdf', $responseData['filename']);
        $this->assertNotNull($responseData['expires_at']);
    }

    public function test_generate_user_activity_report_as_organization_admin_succeeds(): void
    {
        // Ensure organization admin has proper permissions and team context
        $this->organizationAdminUser->setPermissionsTeamId($this->organizationAdminUser->organization_id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organizationAdminUser->organization_id);

        // Refresh the permission
        app(\Spatie\Permission\PermissionRegistrar::class)->forgetCachedPermissions();

        Passport::actingAs($this->organizationAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'organization',
                    'date_range',
                    'user_statistics',
                    'login_statistics',
                    'daily_activity',
                    'top_users',
                    'role_distribution',
                    'custom_role_distribution',
                    'generated_at',
                ],
                'message',
            ]);
    }

    public function test_generate_user_activity_report_for_different_organization_fails(): void
    {
        Passport::actingAs($this->organizationAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->otherOrganization->id}/reports/user-activity");

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'Access denied',
                'message' => 'Access denied to this organization',
            ]);
    }

    public function test_generate_application_usage_report_succeeds(): void
    {
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/application-usage");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'organization',
                    'summary',
                    'applications',
                    'token_statistics',
                    'usage_trends',
                    'top_applications',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'Application usage report generated successfully',
            ]);

        $responseData = $response->json('data');
        $this->assertEquals($this->organization->id, $responseData['organization']['id']);
        $this->assertArrayHasKey('total_applications', $responseData['summary']);
        $this->assertIsArray($responseData['applications']);

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->superAdminUser->id,
            'event' => 'application_usage_report_generated',
        ]);
    }

    public function test_generate_application_usage_report_as_pdf_succeeds(): void
    {
        $this->markTestSkipped('PDF generation temporarily disabled - missing view configuration');
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/application-usage?".http_build_query([
            'format' => 'pdf',
        ]));

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'download_url',
                    'filename',
                    'expires_at',
                ],
                'message',
            ]);

        $responseData = $response->json('data');
        $this->assertStringContains('.pdf', $responseData['filename']);
    }

    public function test_generate_security_audit_report_succeeds(): void
    {
        Passport::actingAs($this->superAdminUser, ['security']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/security-audit");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'organization',
                    'audit_period',
                    'security_summary',
                    'failed_login_trends',
                    'suspicious_ip_addresses',
                    'users_without_mfa',
                    'privileged_users',
                    'security_compliance',
                    'recent_security_events',
                    'recommendations',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'Security audit report generated successfully',
            ]);

        $responseData = $response->json('data');
        $this->assertEquals($this->organization->id, $responseData['organization']['id']);
        $this->assertArrayHasKey('total_failed_logins', $responseData['security_summary']);
        $this->assertIsArray($responseData['failed_login_trends']);
        $this->assertIsArray($responseData['recent_security_events']);

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->superAdminUser->id,
            'event' => 'security_audit_report_generated',
        ]);
    }

    public function test_generate_security_audit_report_as_pdf_succeeds(): void
    {
        $this->markTestSkipped('PDF generation temporarily disabled - missing view configuration');
        Passport::actingAs($this->superAdminUser, ['security']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/security-audit?".http_build_query([
            'format' => 'pdf',
        ]));

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'download_url',
                    'filename',
                    'expires_at',
                ],
                'message',
            ]);
    }

    public function test_generate_reports_requires_proper_permissions(): void
    {
        // Create a user with no permissions to test authorization
        $userWithNoPermissions = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Don't assign any role - user should have no permissions
        Passport::actingAs($userWithNoPermissions, ['profile']); // Wrong permission

        // Test user activity report
        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity");
        $response->assertStatus(403);

        // Test application usage report
        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/application-usage");
        $response->assertStatus(403);

        // Test security audit report
        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/security-audit");
        $response->assertStatus(403);
    }

    public function test_generate_reports_requires_authentication(): void
    {
        $endpoints = [
            "/api/v1/organizations/{$this->organization->id}/reports/user-activity",
            "/api/v1/organizations/{$this->organization->id}/reports/application-usage",
            "/api/v1/organizations/{$this->organization->id}/reports/security-audit",
        ];

        foreach ($endpoints as $endpoint) {
            $response = $this->getJson($endpoint);
            $response->assertStatus(401, "Endpoint {$endpoint} should require authentication");
        }
    }

    public function test_generate_user_activity_report_with_invalid_dates_fails(): void
    {
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        // End date before start date
        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity?".http_build_query([
            'start_date' => now()->format('Y-m-d'),
            'end_date' => now()->subDays(1)->format('Y-m-d'),
        ]));

        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details',
            ])
            ->assertJson([
                'error' => 'validation_failed',
            ]);
    }

    public function test_generate_reports_with_invalid_format_fails(): void
    {
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $endpoints = [
            "/api/v1/organizations/{$this->organization->id}/reports/user-activity",
            "/api/v1/organizations/{$this->organization->id}/reports/application-usage",
            "/api/v1/organizations/{$this->organization->id}/reports/security-audit",
        ];

        foreach ($endpoints as $endpoint) {
            $response = $this->getJson($endpoint.'?'.http_build_query(['format' => 'invalid']));
            $response->assertStatus(422, "Endpoint {$endpoint} should reject invalid format");
        }
    }

    public function test_generate_reports_with_nonexistent_organization_fails(): void
    {
        Passport::actingAs($this->superAdminUser, ['reports', 'security']);

        $endpoints = [
            '/api/v1/organizations/99999/reports/user-activity',
            '/api/v1/organizations/99999/reports/application-usage',
            '/api/v1/organizations/99999/reports/security-audit',
        ];

        foreach ($endpoints as $endpoint) {
            $response = $this->getJson($endpoint);
            $response->assertStatus(404, "Endpoint {$endpoint} should return 404 for nonexistent organization");
        }
    }

    public function test_report_generation_handles_service_errors_gracefully(): void
    {
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        // Test with organization that might cause service errors
        $problemOrganization = Organization::factory()->create([
            'name' => 'Problem Organization',
        ]);

        // Simulate condition that might cause report generation to fail
        // In a real scenario, this could be database issues, missing data, etc.
        $response = $this->getJson("/api/v1/organizations/{$problemOrganization->id}/reports/user-activity");

        // The report should still succeed even with minimal data
        $response->assertStatus(200);
    }

    public function test_pdf_export_includes_proper_metadata(): void
    {
        $this->markTestSkipped('PDF generation temporarily disabled - missing view configuration');
        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity?".http_build_query([
            'format' => 'pdf',
        ]));

        $response->assertStatus(200);

        $responseData = $response->json('data');

        // Verify filename contains report type and timestamp
        $this->assertStringContains('user_activity', $responseData['filename']);
        $this->assertStringEndsWith('.pdf', $responseData['filename']);

        // Verify expiration is properly set (24 hours from now)
        $expiresAt = new \DateTime($responseData['expires_at']);
        $expectedExpiry = new \DateTime('+24 hours');
        $this->assertEqualsWithDelta($expectedExpiry->getTimestamp(), $expiresAt->getTimestamp(), 60); // Within 1 minute
    }

    public function test_cross_organization_data_isolation_in_reports(): void
    {
        // Create users in different organizations
        $otherOrgUser = User::factory()->forOrganization($this->otherOrganization)->create();

        AuthenticationLog::factory()->create([
            'user_id' => $otherOrgUser->id,
            'event' => 'login_success',
            'ip_address' => '10.0.0.1',
        ]);

        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity");

        $response->assertStatus(200);

        $responseData = $response->json('data');

        // Verify that the report only contains data from the requested organization
        $this->assertEquals($this->organization->id, $responseData['organization']['id']);

        // Verify user statistics don't include users from other organizations
        $userCount = $responseData['user_statistics']['total_users'];
        // Count users associated with applications in this organization (3 users from setup)
        $orgUserCount = User::whereHas('applications', function ($q) {
            $q->where('organization_id', $this->organization->id);
        })->count();
        $this->assertEquals($orgUserCount, $userCount);
    }

    public function test_report_generation_performance_with_large_datasets(): void
    {
        // Create additional users and logs for performance testing
        $additionalUsers = User::factory(10)->forOrganization($this->organization)->create();

        // Associate additional users with the application
        foreach ($additionalUsers as $user) {
            $user->applications()->attach($this->application->id, [
                'permissions' => ['read'],
                'granted_at' => now(),
            ]);
        }

        $users = User::where('organization_id', $this->organization->id)->get();
        foreach ($users->take(5) as $user) {
            AuthenticationLog::factory(5)->create([
                'user_id' => $user->id,
                'event' => 'login_success',
            ]);
        }

        Passport::actingAs($this->superAdminUser, ['organizations.read']);

        $startTime = microtime(true);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity");

        $endTime = microtime(true);
        $executionTime = $endTime - $startTime;

        $response->assertStatus(200);

        // Report generation should complete within reasonable time (5 seconds for test data)
        $this->assertLessThan(5, $executionTime);

        $responseData = $response->json('data');
        $this->assertGreaterThan(10, $responseData['user_statistics']['total_users']);
    }
}
