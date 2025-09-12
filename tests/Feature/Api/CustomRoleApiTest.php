<?php

namespace Tests\Feature\Api;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Tests\TestCase;

class CustomRoleApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private Organization $otherOrganization;

    private User $adminUser;

    private User $regularUser;

    private User $superAdmin;

    private CustomRole $customRole;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->otherOrganization = Organization::factory()->create();

        // Use proper test helpers that handle organization-scoped permissions correctly
        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        $this->superAdmin = $this->createApiSuperAdmin([
            'organization_id' => $this->organization->id,
        ]);

        // Create a test custom role
        $this->customRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
            'name' => 'Test Role',
            'display_name' => 'Test Custom Role',
            'permissions' => ['users.read', 'users.create'],
        ]);
    }

    public function test_index_returns_paginated_custom_roles(): void
    {
        // Create additional roles for pagination testing
        CustomRole::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
        ]);

        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'organization_id',
                        'name',
                        'display_name',
                        'description',
                        'permissions',
                        'permissions_count',
                        'is_system',
                        'is_active',
                        'users_count',
                        'can_be_deleted',
                        'created_at',
                        'updated_at',
                    ],
                ],
                'meta' => [
                    'pagination' => [
                        'current_page',
                        'per_page',
                        'total',
                        'total_pages',
                    ],
                    'available_permissions',
                    'permission_categories',
                ],
                'links',
            ]);

        $this->assertCount(4, $response->json('data')); // 1 from setUp + 3 factory created
    }

    public function test_index_with_search_filters_roles(): void
    {
        CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Special Search Role',
            'display_name' => 'Special Role for Searching',
        ]);

        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles?search=Special");

        $response->assertStatus(200);
        $data = $response->json('data');

        $this->assertCount(1, $data);
        $this->assertStringContainsString('Special', $data[0]['name']);
    }

    public function test_index_filters_by_is_system(): void
    {
        CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => true,
        ]);

        CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => false,
        ]);

        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles?is_system=1");

        $response->assertStatus(200);

        foreach ($response->json('data') as $role) {
            $this->assertTrue($role['is_system']);
        }
    }

    public function test_index_prevents_cross_organization_access(): void
    {
        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->otherOrganization->id}/custom-roles");

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'Access denied',
                'message' => 'Access denied to this organization',
            ]);
    }

    public function test_store_creates_custom_role_successfully(): void
    {
        Passport::actingAs($this->adminUser, ['roles.create']);

        $roleData = [
            'name' => 'New Custom Role',
            'display_name' => 'New Custom Role Display',
            'description' => 'Description for new custom role',
            'permissions' => ['users.read', 'applications.read'],
            'is_active' => true,
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", $roleData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'display_name',
                    'description',
                    'permissions',
                    'is_system',
                    'is_active',
                    'creator',
                ],
                'message',
            ])
            ->assertJson([
                'data' => [
                    'name' => 'New Custom Role',
                    'display_name' => 'New Custom Role Display',
                    'permissions' => ['users.read', 'applications.read'],
                    'is_system' => false,
                    'is_active' => true,
                ],
                'message' => 'Custom role created successfully',
            ]);

        $this->assertDatabaseHas('custom_roles', [
            'name' => 'New Custom Role',
            'organization_id' => $this->organization->id,
            'created_by' => $this->adminUser->id,
        ]);

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->adminUser->id,
            'event' => 'custom_role_created',
        ]);
    }

    public function test_store_validates_required_fields(): void
    {
        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.create']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", []);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'success',
                'error',
                'error_description',
                'errors',
            ])
            ->assertJsonValidationErrors(['name', 'permissions']);
    }

    public function test_store_validates_unique_name_within_organization(): void
    {
        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.create']);

        $roleData = [
            'name' => $this->customRole->name, // Duplicate name
            'permissions' => ['users.read'],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", $roleData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('name');
    }

    public function test_store_validates_invalid_permissions(): void
    {
        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.create']);

        $roleData = [
            'name' => 'Test Role Invalid',
            'permissions' => ['invalid.permission', 'users.read'],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", $roleData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('permissions.0');
    }

    public function test_store_requires_permission(): void
    {
        Passport::actingAs($this->regularUser, ['roles.read']); // Only read permission

        $roleData = [
            'name' => 'Unauthorized Role',
            'permissions' => ['users.read'],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", $roleData);

        $response->assertStatus(403);
    }

    public function test_show_returns_custom_role_details(): void
    {
        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'display_name',
                    'permissions',
                    'users_count',
                    'creator',
                    'users', // Detailed view includes users
                ],
            ])
            ->assertJson([
                'data' => [
                    'id' => $this->customRole->id,
                    'name' => $this->customRole->name,
                    'permissions' => $this->customRole->permissions,
                ],
            ]);
    }

    public function test_show_returns_404_for_nonexistent_role(): void
    {
        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles/999999");

        $response->assertStatus(404);
    }

    public function test_show_prevents_cross_organization_access(): void
    {
        $otherRole = CustomRole::factory()->create([
            'organization_id' => $this->otherOrganization->id,
        ]);

        Passport::actingAs($this->adminUser, ['roles.read']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$otherRole->id}");

        $response->assertStatus(404); // Should not find role from different org
    }

    public function test_update_modifies_custom_role_successfully(): void
    {
        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.update']);

        $updateData = [
            'display_name' => 'Updated Display Name',
            'description' => 'Updated description',
            'permissions' => ['users.read', 'applications.read', 'organization.read'],
            'is_active' => false,
        ];

        $response = $this->putJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}", $updateData);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data',
                'message',
            ])
            ->assertJson([
                'data' => [
                    'display_name' => 'Updated Display Name',
                    'description' => 'Updated description',
                    'permissions' => ['users.read', 'applications.read', 'organization.read'],
                    'is_active' => false,
                ],
                'message' => 'Custom role updated successfully',
            ]);

        $this->assertDatabaseHas('custom_roles', [
            'id' => $this->customRole->id,
            'display_name' => 'Updated Display Name',
        ]);

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->adminUser->id,
            'event' => 'custom_role_updated',
        ]);
    }

    public function test_update_prevents_modifying_system_roles(): void
    {
        $systemRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => true,
        ]);

        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.update']);

        $response = $this->putJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$systemRole->id}", [
            'display_name' => 'Cannot Update System Role',
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'forbidden',
                'error_description' => 'System roles cannot be modified.',
            ]);
    }

    public function test_update_validates_unique_name(): void
    {
        $otherRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Other Role',
        ]);

        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.update']);

        $response = $this->putJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}", [
            'name' => 'Other Role', // Duplicate name
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('name');
    }

    public function test_destroy_deletes_custom_role_successfully(): void
    {
        $deletableRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => false,
        ]);

        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.delete']);

        $response = $this->deleteJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$deletableRole->id}");

        $response->assertStatus(204);

        $this->assertDatabaseHas('custom_roles', [
            'id' => $deletableRole->id,
        ]);

        // Verify the role is soft deleted
        $this->assertNotNull(CustomRole::withTrashed()->find($deletableRole->id)->deleted_at);

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->adminUser->id,
            'event' => 'custom_role_deleted',
        ]);
    }

    public function test_destroy_prevents_deleting_system_roles(): void
    {
        $systemRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => true,
        ]);

        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.delete']);

        $response = $this->deleteJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$systemRole->id}");

        $response->assertStatus(409)
            ->assertJsonStructure([
                'success',
                'error' => [
                    'message',
                    'code',
                ],
            ])
            ->assertJsonPath('error.message', 'System roles cannot be deleted.');
    }

    public function test_destroy_prevents_deleting_roles_assigned_to_users(): void
    {
        // Assign the role to a user
        $this->customRole->users()->attach($this->regularUser->id, [
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.delete']);

        $response = $this->deleteJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}");

        $response->assertStatus(409)
            ->assertJsonStructure([
                'success',
                'error' => [
                    'message',
                    'code',
                ],
            ])
            ->assertJsonPath('error.message', 'Role is assigned to users and cannot be deleted.');
    }

    public function test_permissions_returns_available_permissions(): void
    {
        // This endpoint requires authentication
        Passport::actingAs($this->adminUser);

        $response = $this->getJson('/api/v1/config/permissions');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'permissions',
                    'categories',
                ],
            ]);

        // Verify it returns arrays
        $data = $response->json('data');
        $this->assertIsArray($data['permissions']);
        $this->assertIsArray($data['categories']);
    }

    public function test_assign_users_adds_users_to_role(): void
    {
        $user1 = User::factory()->forOrganization($this->organization)->create();
        $user2 = User::factory()->forOrganization($this->organization)->create();

        Passport::actingAs($this->adminUser, ['roles.assign']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/assign-users", [
            'user_ids' => [$user1->id, $user2->id],
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Custom role assigned to 2 users successfully',
            ]);

        // Verify users were assigned to the role
        $this->assertTrue($this->customRole->users()->where('user_id', $user1->id)->exists());
        $this->assertTrue($this->customRole->users()->where('user_id', $user2->id)->exists());

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->adminUser->id,
            'event' => 'custom_role_users_assigned',
        ]);
    }

    public function test_assign_users_validates_user_ids(): void
    {
        Passport::actingAs($this->adminUser, ['roles.assign']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/assign-users", [
            'user_ids' => [999999, 888888], // Non-existent users
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('user_ids.0');
    }

    public function test_assign_users_prevents_cross_organization_access(): void
    {
        Passport::actingAs($this->adminUser, ['roles.assign']);

        $response = $this->postJson("/api/v1/organizations/{$this->otherOrganization->id}/custom-roles/{$this->customRole->id}/assign-users", [
            'user_ids' => [$this->regularUser->id],
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'error' => 'Access denied',
                'message' => 'Access denied to this organization',
            ]);
    }

    public function test_remove_users_removes_users_from_role(): void
    {
        $user1 = User::factory()->forOrganization($this->organization)->create();
        $user2 = User::factory()->forOrganization($this->organization)->create();

        // First assign users to the role
        $this->customRole->users()->attach([
            $user1->id => ['granted_at' => now(), 'granted_by' => $this->adminUser->id],
            $user2->id => ['granted_at' => now(), 'granted_by' => $this->adminUser->id],
        ]);

        Passport::actingAs($this->adminUser, ['roles.assign']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/remove-users", [
            'user_ids' => [$user1->id, $user2->id],
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Custom role removed from 2 users successfully',
            ]);

        // Verify users were removed from the role
        $this->assertFalse($this->customRole->users()->where('user_id', $user1->id)->exists());
        $this->assertFalse($this->customRole->users()->where('user_id', $user2->id)->exists());

        // Verify authentication log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->adminUser->id,
            'event' => 'custom_role_users_removed',
        ]);
    }

    public function test_remove_users_validates_user_ids(): void
    {
        Passport::actingAs($this->adminUser, ['roles.assign']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/remove-users", [
            'user_ids' => [999999], // Non-existent user
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('user_ids.0');
    }

    public function test_super_admin_can_access_any_organization(): void
    {
        // Super Admin should NOT have team context - they are global
        $this->superAdmin->setPermissionsTeamId(null);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId(null);

        Passport::actingAs($this->superAdmin, ['roles.read']);

        // Super admin should be able to access any organization's roles
        $response = $this->getJson("/api/v1/organizations/{$this->otherOrganization->id}/custom-roles");

        $response->assertStatus(200);
    }

    public function test_all_custom_role_endpoints_require_authentication(): void
    {
        $endpoints = [
            ['GET', "/api/v1/organizations/{$this->organization->id}/custom-roles"],
            ['POST', "/api/v1/organizations/{$this->organization->id}/custom-roles"],
            ['GET', "/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}"],
            ['PUT', "/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}"],
            ['DELETE', "/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}"],
            ['POST', "/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/assign-users"],
            ['POST', "/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/remove-users"],
        ];

        foreach ($endpoints as [$method, $endpoint]) {
            $response = $this->json($method, $endpoint);
            $response->assertStatus(401, "Endpoint {$method} {$endpoint} should require authentication");
        }

        // Test authenticated endpoint too
        Passport::actingAs($this->adminUser);
        $response = $this->getJson('/api/v1/config/permissions');
        $response->assertStatus(200); // Should work with auth
    }

    public function test_role_permissions_are_properly_validated(): void
    {
        // Set team context for Spatie permissions
        $this->adminUser->setPermissionsTeamId($this->organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

        Passport::actingAs($this->adminUser, ['roles.create']);

        // Test with mix of valid and invalid permissions
        $roleData = [
            'name' => 'Permission Test Role',
            'permissions' => [
                'users.read', // Valid
                'applications.create', // Valid
                'invalid.permission', // Invalid
                'another.invalid.one', // Invalid
            ],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", $roleData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['permissions.2', 'permissions.3']);
    }

    public function test_bulk_operations_respect_limits(): void
    {
        // Create fewer users but generate a large array of IDs to test the limit
        $users = User::factory()->count(10)->forOrganization($this->organization)->create();
        $baseIds = $users->pluck('id')->toArray();

        // Generate 1001 IDs (mix of real and fake to test validation)
        $userIds = array_merge($baseIds, range(9999, 9999 + 991));

        Passport::actingAs($this->adminUser, ['roles.assign']);

        // Try to assign more than the maximum allowed (1000)
        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$this->customRole->id}/assign-users", [
            'user_ids' => $userIds,
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('user_ids');
    }
}
