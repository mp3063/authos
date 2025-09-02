<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class UserManagementApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;
    private User $adminUser;
    private User $regularUser;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization = Organization::factory()->create();
        
        // Create required roles
        Role::create(['name' => 'user', 'guard_name' => 'web']);
        Role::create(['name' => 'super admin', 'guard_name' => 'web']);
        Role::create(['name' => 'organization admin', 'guard_name' => 'web']);
        
        $this->adminUser = $this->createSuperAdmin();
        $this->regularUser = User::factory()
            ->forOrganization($this->organization)
            ->create();
    }

    public function test_list_users_returns_paginated_results(): void
    {
        // Create additional users
        User::factory()
            ->count(15)
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->adminUser, ['users.view']);

        $response = $this->getJson('/api/v1/users');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'email',
                        'organization' => [
                            'id',
                            'name',
                            'slug',
                        ],
                        'roles',
                        'is_active',
                        'mfa_enabled',
                        'created_at',
                        'last_login_at',
                    ]
                ],
                'links',
                'meta' => [
                    'current_page',
                    'per_page',
                    'total',
                ],
            ])
            ->assertJsonPath('meta.per_page', 15);
    }

    public function test_list_users_supports_filtering_and_search(): void
    {
        $activeUser = User::factory()
            ->forOrganization($this->organization)
            ->create(['name' => 'John Active', 'is_active' => true]);

        $inactiveUser = User::factory()
            ->forOrganization($this->organization)
            ->inactive()
            ->create(['name' => 'Jane Inactive']);

        Passport::actingAs($this->adminUser, ['users.view']);

        // Test active filter
        $response = $this->getJson('/api/v1/users?filter[is_active]=true');
        $response->assertStatus(200);
        $userIds = collect($response->json('data'))->pluck('id')->toArray();
        $this->assertContains($activeUser->id, $userIds);
        $this->assertNotContains($inactiveUser->id, $userIds);

        // Test search
        $response = $this->getJson('/api/v1/users?search=John');
        $response->assertStatus(200);
        $userIds = collect($response->json('data'))->pluck('id')->toArray();
        $this->assertContains($activeUser->id, $userIds);
        $this->assertNotContains($inactiveUser->id, $userIds);
    }

    public function test_create_user_creates_new_user_with_role(): void
    {
        Passport::actingAs($this->adminUser, ['users.create']);

        $userData = [
            'name' => 'New User',
            'email' => 'newuser@example.com',
            'password' => 'password123',
            'organization_id' => $this->organization->id,
            'role' => 'user',
            'profile' => [
                'bio' => 'Test user',
                'location' => 'Test City',
            ],
        ];

        $response = $this->postJson('/api/v1/users', $userData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'id',
                'name',
                'email',
                'organization_id',
                'roles',
                'profile',
                'is_active',
            ])
            ->assertJson([
                'name' => 'New User',
                'email' => 'newuser@example.com',
                'organization_id' => $this->organization->id,
                'is_active' => true,
            ]);

        $this->assertDatabaseHas('users', [
            'email' => 'newuser@example.com',
            'organization_id' => $this->organization->id,
        ]);

        $user = User::where('email', 'newuser@example.com')->first();
        $this->assertTrue($user->hasRole('user'));
    }

    public function test_get_user_returns_detailed_user_information(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->withMfa()
            ->create();

        Passport::actingAs($this->adminUser, ['users.view']);

        $response = $this->getJson("/api/v1/users/{$user->id}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'id',
                'name',
                'email',
                'organization' => [
                    'id',
                    'name',
                    'slug',
                ],
                'roles',
                'permissions',
                'profile',
                'mfa_enabled',
                'is_active',
                'created_at',
                'updated_at',
                'last_login_at',
                'applications_count',
                'sessions_count',
            ])
            ->assertJson([
                'id' => $user->id,
                'mfa_enabled' => true,
            ]);
    }

    public function test_update_user_updates_user_information(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create(['name' => 'Old Name']);

        Passport::actingAs($this->adminUser, ['users.edit']);

        $updateData = [
            'name' => 'Updated Name',
            'profile' => [
                'bio' => 'Updated bio',
                'location' => 'Updated location',
            ],
            'is_active' => false,
        ];

        $response = $this->putJson("/api/v1/users/{$user->id}", $updateData);

        $response->assertStatus(200)
            ->assertJson([
                'id' => $user->id,
                'name' => 'Updated Name',
                'is_active' => false,
            ]);

        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'name' => 'Updated Name',
            'is_active' => false,
        ]);
    }

    public function test_delete_user_soft_deletes_user(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->adminUser, ['users.delete']);

        $response = $this->deleteJson("/api/v1/users/{$user->id}");

        $response->assertStatus(204);

        $this->assertSoftDeleted('users', [
            'id' => $user->id,
        ]);
    }

    public function test_get_user_applications_returns_user_app_relationships(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $app1 = Application::factory()->forOrganization($this->organization)->create();
        $app2 = Application::factory()->forOrganization($this->organization)->create();

        $user->applications()->attach([
            $app1->id => [
                'permissions' => ['read', 'write'],
                'last_accessed_at' => now()->subDays(2),
                'access_count' => 10,
            ],
            $app2->id => [
                'permissions' => ['read'],
                'last_accessed_at' => now()->subDays(1),
                'access_count' => 5,
            ],
        ]);

        Passport::actingAs($this->adminUser, ['users.view']);

        $response = $this->getJson("/api/v1/users/{$user->id}/applications");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'permissions',
                        'last_accessed_at',
                        'access_count',
                    ]
                ]
            ])
            ->assertJsonCount(2, 'data');
    }

    public function test_grant_application_access_creates_user_app_relationship(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $application = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->adminUser, ['users.edit']);

        $accessData = [
            'permissions' => ['read', 'write'],
        ];

        $response = $this->postJson("/api/v1/users/{$user->id}/applications", [
            'application_id' => $application->id,
            'permissions' => ['read', 'write'],
        ]);

        $response->assertStatus(201)
            ->assertJson([
                'message' => 'Application access granted successfully',
            ]);

        $this->assertDatabaseHas('user_applications', [
            'user_id' => $user->id,
            'application_id' => $application->id,
        ]);
    }

    public function test_revoke_application_access_removes_relationship(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $application = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        $user->applications()->attach($application->id, [
            'permissions' => ['read'],
            'granted_at' => now(),
        ]);

        Passport::actingAs($this->adminUser, ['users.edit']);

        $response = $this->deleteJson("/api/v1/users/{$user->id}/applications/{$application->id}");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Application access revoked successfully',
            ]);

        $this->assertDatabaseMissing('user_applications', [
            'user_id' => $user->id,
            'application_id' => $application->id,
        ]);
    }

    public function test_get_user_roles_returns_assigned_roles(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $role1 = Role::create(['name' => 'test-role-1', 'guard_name' => 'web']);
        $role2 = Role::create(['name' => 'test-role-2', 'guard_name' => 'web']);

        $user->assignRole([$role1, $role2]);

        Passport::actingAs($this->adminUser, ['users.view']);

        $response = $this->getJson("/api/v1/users/{$user->id}/roles");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'display_name',
                        'permissions',
                    ]
                ]
            ])
            ->assertJsonCount(2, 'data');
    }

    public function test_assign_role_to_user_creates_role_assignment(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $role = Role::create(['name' => 'test-role', 'guard_name' => 'web']);

        Passport::actingAs($this->adminUser, ['users.edit']);

        $response = $this->postJson("/api/v1/users/{$user->id}/roles", [
            'role_id' => $role->id,
        ]);

        $response->assertStatus(201)
            ->assertJson([
                'message' => 'Role assigned successfully',
            ]);

        $this->assertTrue($user->hasRole($role));
    }

    public function test_remove_role_from_user_removes_assignment(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $role = Role::create(['name' => 'test-role', 'guard_name' => 'web']);
        $user->assignRole($role);

        Passport::actingAs($this->adminUser, ['users.edit']);

        $response = $this->deleteJson("/api/v1/users/{$user->id}/roles/{$role->id}");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Role removed successfully',
            ]);

        $this->assertFalse($user->hasRole($role));
    }

    public function test_get_user_sessions_returns_active_sessions(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $app1 = Application::factory()->create();
        $app2 = Application::factory()->create();

        // Create active sessions
        SSOSession::factory()
            ->count(2)
            ->forUser($user)
            ->forApplication($app1)
            ->recentlyActive()
            ->create();

        // Create expired session (should not appear)
        SSOSession::factory()
            ->forUser($user)
            ->forApplication($app2)
            ->expired()
            ->create();

        Passport::actingAs($this->adminUser, ['users.view']);

        $response = $this->getJson("/api/v1/users/{$user->id}/sessions");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'application' => [
                            'id',
                            'name',
                        ],
                        'ip_address',
                        'user_agent',
                        'last_activity_at',
                        'expires_at',
                    ]
                ]
            ])
            ->assertJsonCount(2, 'data');
    }

    public function test_revoke_all_user_sessions_invalidates_sessions(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $sessions = SSOSession::factory()
            ->count(3)
            ->forUser($user)
            ->recentlyActive()
            ->create();

        Passport::actingAs($this->adminUser, ['users.edit']);

        $response = $this->deleteJson("/api/v1/users/{$user->id}/sessions");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'All user sessions revoked successfully',
                'revoked_count' => 3,
            ]);

        foreach ($sessions as $session) {
            $session->refresh();
            $this->assertNotNull($session->logged_out_at);
        }
    }

    public function test_revoke_specific_user_session_invalidates_session(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $session = SSOSession::factory()
            ->forUser($user)
            ->recentlyActive()
            ->create();

        Passport::actingAs($this->adminUser, ['users.edit']);

        $response = $this->deleteJson("/api/v1/users/{$user->id}/sessions/{$session->id}");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Session revoked successfully',
            ]);

        $session->refresh();
        $this->assertNotNull($session->logged_out_at);
    }

    public function test_unauthorized_user_cannot_access_users_api(): void
    {
        $unauthorizedUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($unauthorizedUser, ['profile']);

        $response = $this->getJson('/api/v1/users');

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Insufficient permissions',
            ]);
    }

    public function test_organization_isolation_prevents_cross_organization_access(): void
    {
        $otherOrganization = Organization::factory()->create();
        $otherUser = User::factory()
            ->forOrganization($otherOrganization)
            ->create();

        Passport::actingAs($this->adminUser, ['users.view']);

        // Try to access user from different organization
        $response = $this->getJson("/api/v1/users/{$otherUser->id}");

        $response->assertStatus(404);
    }

    public function test_api_validates_required_fields_for_user_creation(): void
    {
        Passport::actingAs($this->adminUser, ['users.create']);

        $response = $this->postJson('/api/v1/users', [
            'name' => '',
            'email' => 'invalid-email',
            'password' => '123', // Too short
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password', 'organization_id']);
    }

    public function test_api_enforces_unique_email_constraint(): void
    {
        $existingUser = User::factory()
            ->forOrganization($this->organization)
            ->create(['email' => 'existing@example.com']);

        Passport::actingAs($this->adminUser, ['users.create']);

        $response = $this->postJson('/api/v1/users', [
            'name' => 'New User',
            'email' => 'existing@example.com',
            'password' => 'password123',
            'organization_id' => $this->organization->id,
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    public function test_bulk_operations_handle_multiple_users(): void
    {
        $users = User::factory()
            ->count(5)
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->adminUser, ['users.edit']);

        $userIds = $users->pluck('id')->toArray();

        // Bulk deactivate users
        $response = $this->patchJson('/api/v1/users/bulk', [
            'user_ids' => $userIds,
            'action' => 'deactivate',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Bulk operation completed successfully',
                'affected_count' => 5,
            ]);

        foreach ($users as $user) {
            $this->assertDatabaseHas('users', [
                'id' => $user->id,
                'is_active' => false,
            ]);
        }
    }
}