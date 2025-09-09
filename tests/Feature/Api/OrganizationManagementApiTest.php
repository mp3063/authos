<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class OrganizationManagementApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;
    private User $superAdmin;
    private User $orgAdmin;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization = Organization::factory()->create();
        
        // Create required roles for API guard
        Role::create(['name' => 'super admin', 'guard_name' => 'api']);
        Role::create(['name' => 'organization admin', 'guard_name' => 'api']);
        Role::create(['name' => 'user', 'guard_name' => 'api']);
        
        // Create API users with proper permissions
        $this->superAdmin = $this->createApiSuperAdmin(['organization_id' => $this->organization->id]);
        $this->orgAdmin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
    }

    public function test_list_organizations_returns_paginated_results(): void
    {
        // Create additional organizations
        Organization::factory()->count(10)->create();

        Passport::actingAs($this->superAdmin, ['organizations.read']);

        $response = $this->getJson('/api/v1/organizations');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'slug',
                        'description',
                        'website',
                        'logo',
                        'is_active',
                        'settings',
                        'users_count',
                        'applications_count',
                        'created_at',
                    ]
                ],
                'links',
                'meta',
            ]);
    }

    public function test_list_organizations_supports_filtering(): void
    {
        $activeOrg = Organization::factory()->create(['is_active' => true, 'name' => 'Active Corp']);
        $inactiveOrg = Organization::factory()->create(['is_active' => false, 'name' => 'Disabled Corp']);

        Passport::actingAs($this->superAdmin, ['organizations.read']);

        // Filter by active status
        $response = $this->getJson('/api/v1/organizations?filter[is_active]=true');
        
        $response->assertStatus(200);
        $orgIds = collect($response->json('data'))->pluck('id')->toArray();
        $this->assertContains($activeOrg->id, $orgIds);
        $this->assertNotContains($inactiveOrg->id, $orgIds);

        // Search by name
        $response = $this->getJson('/api/v1/organizations?search=Active');
        
        $response->assertStatus(200);
        $orgIds = collect($response->json('data'))->pluck('id')->toArray();
        $this->assertContains($activeOrg->id, $orgIds);
        $this->assertNotContains($inactiveOrg->id, $orgIds);
    }

    public function test_create_organization_creates_new_organization(): void
    {
        Passport::actingAs($this->superAdmin, ['organizations.create']);

        $orgData = [
            'name' => 'New Organization',
            'description' => 'A new organization for testing',
            'website' => 'https://example.com',
            'settings' => [
                'require_mfa' => true,
                'password_policy' => [
                    'min_length' => 10,
                    'require_uppercase' => true,
                ],
                'session_timeout' => 3600,
            ],
        ];

        $response = $this->postJson('/api/v1/organizations', $orgData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'id',
                'name',
                'slug',
                'description',
                'website',
                'settings',
                'is_active',
            ])
            ->assertJson([
                'name' => 'New Organization',
                'is_active' => true,
            ]);

        $this->assertDatabaseHas('organizations', [
            'name' => 'New Organization',
            'slug' => 'new-organization',
        ]);
    }

    public function test_get_organization_returns_detailed_information(): void
    {
        // Add some related data
        $applications = Application::factory()->count(3)->forOrganization($this->organization)->create();
        $users = User::factory()->count(5)->forOrganization($this->organization)->create();
        
        // Attach users to applications so they count properly
        foreach ($users as $user) {
            $user->applications()->attach($applications->first()->id, [
                'granted_at' => now(),
                'login_count' => 0,
            ]);
        }

        Passport::actingAs($this->superAdmin, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'id',
                'name',
                'slug',
                'description',
                'website',
                'logo',
                'settings',
                'is_active',
                'users_count',
                'applications_count',
                'recent_activity',
                'created_at',
                'updated_at',
            ])
            ->assertJson([
                'id' => $this->organization->id,
                'users_count' => 5,
                'applications_count' => 3,
            ]);
    }

    public function test_update_organization_updates_information(): void
    {
        Passport::actingAs($this->superAdmin, ['organizations.update']);

        $updateData = [
            'name' => 'Updated Organization Name',
            'description' => 'Updated description',
            'settings' => [
                'require_mfa' => false,
                'session_timeout' => 300,
            ],
        ];

        $response = $this->putJson("/api/v1/organizations/{$this->organization->id}", $updateData);

        $response->assertStatus(200)
            ->assertJson([
                'id' => $this->organization->id,
                'name' => 'Updated Organization Name',
                'description' => 'Updated description',
            ]);

        $this->assertDatabaseHas('organizations', [
            'id' => $this->organization->id,
            'name' => 'Updated Organization Name',
        ]);
    }

    public function test_delete_organization_soft_deletes_organization(): void
    {
        $organization = Organization::factory()->create();

        Passport::actingAs($this->superAdmin, ['organizations.delete']);

        $response = $this->deleteJson("/api/v1/organizations/{$organization->id}");

        $response->assertStatus(204);

        $this->assertSoftDeleted('organizations', [
            'id' => $organization->id,
        ]);
    }

    public function test_get_organization_settings_returns_configuration(): void
    {
        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/settings");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'general' => [
                    'require_mfa',
                    'session_timeout',
                    'password_policy',
                ],
                'security' => [
                    'allowed_domains',
                    'sso_enabled',
                ],
                'customization' => [
                    'theme',
                    'branding',
                ],
            ]);
    }

    public function test_update_organization_settings_modifies_configuration(): void
    {
        Passport::actingAs($this->orgAdmin, ['organizations.update']);

        $settingsData = [
            'require_mfa' => true,
            'password_policy' => [
                'min_length' => 12,
                'require_uppercase' => true,
                'require_numbers' => true,
                'require_symbols' => true,
            ],
            'session_timeout' => 1800,
            'allowed_domains' => ['example.com', 'test.com'],
        ];

        $response = $this->putJson("/api/v1/organizations/{$this->organization->id}/settings", $settingsData);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Settings updated successfully',
            ]);

        $this->organization->refresh();
        $this->assertTrue($this->organization->settings['require_mfa']);
        $this->assertEquals(12, $this->organization->settings['password_policy']['min_length']);
    }

    public function test_get_organization_users_returns_member_list(): void
    {
        $users = User::factory()
            ->count(8)
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/users");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'email',
                        'roles',
                        'is_active',
                        'last_login_at',
                        'created_at',
                    ]
                ],
                'meta',
            ]);
    }

    public function test_grant_user_application_access_creates_relationship(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $application = Application::factory()->forOrganization($this->organization)->create();

        Passport::actingAs($this->orgAdmin, ['organizations.manage_users']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/users", [
            'user_id' => $user->id,
            'application_id' => $application->id,
            'permissions' => ['read', 'write'],
        ]);

        $response->assertStatus(201)
            ->assertJson([
                'message' => 'User application access granted successfully',
            ]);

        $this->assertDatabaseHas('user_applications', [
            'user_id' => $user->id,
            'application_id' => $application->id,
        ]);
    }

    public function test_revoke_user_application_access_removes_relationship(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $application = Application::factory()->forOrganization($this->organization)->create();

        // Create existing relationship
        $user->applications()->attach($application->id, [
            'permissions' => ['read'],
            'granted_at' => now(),
        ]);

        Passport::actingAs($this->orgAdmin, ['organizations.manage_users']);

        $response = $this->deleteJson("/api/v1/organizations/{$this->organization->id}/users/{$user->id}/applications/{$application->id}");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'User application access revoked successfully',
            ]);

        $this->assertDatabaseMissing('user_applications', [
            'user_id' => $user->id,
            'application_id' => $application->id,
        ]);
    }

    public function test_get_organization_applications_returns_app_list(): void
    {
        $applications = Application::factory()
            ->count(5)
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/applications");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'description',
                        'client_id',
                        'redirect_uris',
                        'scopes',
                        'is_active',
                        'users_count',
                        'created_at',
                    ]
                ]
            ])
            ->assertJsonCount(5, 'data');
    }

    public function test_get_organization_analytics_returns_metrics(): void
    {
        // Create some test data
        $users = User::factory()->count(10)->forOrganization($this->organization)->create();
        $applications = Application::factory()->count(3)->forOrganization($this->organization)->create();

        // Create authentication logs
        foreach ($users->take(5) as $user) {
            AuthenticationLog::factory()
                ->count(rand(1, 5))
                ->forUser($user)
                ->recent()
                ->create();
        }

        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/analytics");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'summary' => [
                    'total_users',
                    'active_users',
                    'total_applications',
                    'total_logins_today',
                ],
                'user_growth',
                'login_activity',
                'top_applications',
                'security_events',
            ]);
    }

    public function test_get_organization_analytics_supports_date_filtering(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $application = Application::factory()->forOrganization($this->organization)->create();
        
        // Associate user with application
        $user->applications()->attach($application->id);

        // Create logs for different time periods
        AuthenticationLog::factory()
            ->forUser($user)
            ->create([
                'created_at' => now()->subDays(5),
                'event' => 'login_success'
            ]);

        AuthenticationLog::factory()
            ->forUser($user)
            ->create([
                'created_at' => now()->subDays(15),
                'event' => 'login_success'
            ]);

        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/analytics?period=7d");

        $response->assertStatus(200);
        
        // Should only include recent activity within date range  
        $this->assertEquals(1, $response->json('summary.total_logins_today'));
    }

    public function test_organization_admin_can_only_access_own_organization(): void
    {
        $otherOrg = Organization::factory()->create();

        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        // Try to access other organization
        $response = $this->getJson("/api/v1/organizations/{$otherOrg->id}");

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Access denied to this organization',
            ]);
    }

    public function test_regular_user_cannot_access_organization_management(): void
    {
        $regularUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($regularUser, ['profile']);

        $response = $this->getJson('/api/v1/organizations');

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Insufficient permissions',
            ]);
    }

    public function test_create_organization_validates_required_fields(): void
    {
        Passport::actingAs($this->superAdmin, ['organizations.create']);

        $response = $this->postJson('/api/v1/organizations', [
            'name' => '', // Empty name
        ]);

        $response->assertStatus(422)
            ->assertJson([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
            ])
            ->assertJsonPath('details.name.0', 'The name field is required.')
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'name'
                ]
            ]);
    }

    public function test_organization_slug_is_automatically_generated(): void
    {
        Passport::actingAs($this->superAdmin, ['organizations.create']);

        $response = $this->postJson('/api/v1/organizations', [
            'name' => 'Test Organization Inc.',
            'description' => 'Test organization',
        ]);

        $response->assertStatus(201)
            ->assertJsonFragment([
                'slug' => 'test-organization-inc',
            ]);
    }

    public function test_organization_slug_handles_duplicates(): void
    {
        // Create organization with specific name
        Organization::factory()->create(['name' => 'Duplicate Name', 'slug' => 'duplicate-name']);

        Passport::actingAs($this->superAdmin, ['organizations.create']);

        $response = $this->postJson('/api/v1/organizations', [
            'name' => 'Duplicate Name',
            'description' => 'Another organization with same name',
        ]);

        $response->assertStatus(201);
        
        $slug = $response->json('slug');
        $this->assertStringStartsWith('duplicate-name', $slug);
        $this->assertNotEquals('duplicate-name', $slug); // Should have suffix
    }

    public function test_update_organization_settings_validates_configuration(): void
    {
        Passport::actingAs($this->orgAdmin, ['organizations.update']);

        $response = $this->putJson("/api/v1/organizations/{$this->organization->id}/settings", [
            'session_timeout' => -1, // Invalid negative timeout
            'password_policy' => [
                'min_length' => 3, // Too short
            ],
        ]);

        $response->assertStatus(422)
            ->assertJson([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
            ])
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'session_timeout',
                    'password_policy.min_length'
                ]
            ]);
    }

    public function test_organization_analytics_caches_results(): void
    {
        Passport::actingAs($this->orgAdmin, ['organizations.read']);

        // First request
        $response1 = $this->getJson("/api/v1/organizations/{$this->organization->id}/analytics");
        $response1->assertStatus(200);

        // Second request should be faster (cached)
        $startTime = microtime(true);
        $response2 = $this->getJson("/api/v1/organizations/{$this->organization->id}/analytics");
        $endTime = microtime(true);

        $response2->assertStatus(200);
        $this->assertEquals($response1->json(), $response2->json());
        
        // Should be cached (very fast response)
        $this->assertLessThan(0.1, $endTime - $startTime);
    }

    public function test_api_enforces_organization_isolation(): void
    {
        $org1 = Organization::factory()->create();
        $org2 = Organization::factory()->create();
        
        $user1 = User::factory()->forOrganization($org1)->create();
        $user2 = User::factory()->forOrganization($org2)->create();
        
        // Create applications for each organization
        $app1 = Application::factory()->forOrganization($org1)->create();
        $app2 = Application::factory()->forOrganization($org2)->create();
        
        // Grant users access to their respective organization applications
        $user1->applications()->attach($app1->id, ['granted_at' => now()]);
        $user2->applications()->attach($app2->id, ['granted_at' => now()]);
        
        $orgAdmin1 = $this->createApiOrganizationAdmin(['organization_id' => $org1->id]);

        Passport::actingAs($orgAdmin1, ['organizations.read']);

        // Should see user from same organization
        $response = $this->getJson("/api/v1/organizations/{$org1->id}/users");
        $response->assertStatus(200);
        $userIds = collect($response->json('data'))->pluck('id')->toArray();
        $this->assertContains($user1->id, $userIds);

        // Should not see users from other organization
        $response = $this->getJson("/api/v1/organizations/{$org2->id}/users");
        $response->assertStatus(403);
    }
}