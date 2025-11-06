<?php

namespace Tests\Integration\Organizations;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * Custom Roles Integration Tests
 *
 * Tests custom role management within organizations including:
 * - Creating custom roles
 * - Updating custom roles
 * - Deleting custom roles
 * - Listing custom roles
 * - Assigning roles to users
 * - Removing roles from users
 * - Testing role permissions
 * - Role hierarchy
 * - Duplicate name validation
 * - Permission inheritance
 *
 * Verifies:
 * - Role CRUD operations work correctly
 * - Permissions are properly managed
 * - Role assignments are tracked
 * - Validation rules are enforced
 * - Multi-tenant isolation is maintained
 */
class CustomRolesTest extends IntegrationTestCase
{
    protected User $admin;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->admin = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_create_custom_role(): void
    {
        // ARRANGE: Prepare role data
        $roleData = [
            'name' => 'content_manager',
            'display_name' => 'Content Manager',
            'description' => 'Manages content and media',
            'permissions' => [
                'users.read',
                'applications.read',
                'applications.update',
                'organization.read',
            ],
        ];

        // ACT: Create custom role
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", $roleData);

        // ASSERT: Verify response
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'display_name',
                    'description',
                    'permissions',
                    'organization_id',
                    'is_system',
                    'is_active',
                    'created_at',
                ],
            ])
            ->assertJson([
                'data' => [
                    'name' => 'content_manager',
                    'display_name' => 'Content Manager',
                    'is_system' => false,
                    'is_active' => true,
                ],
            ]);

        // ASSERT: Verify database record
        $this->assertDatabaseHas('custom_roles', [
            'organization_id' => $this->organization->id,
            'name' => 'content_manager',
            'display_name' => 'Content Manager',
            'is_system' => false,
        ]);

        // ASSERT: Verify permissions stored
        $role = CustomRole::where('name', 'content_manager')
            ->where('organization_id', $this->organization->id)
            ->first();
        $this->assertNotNull($role);
        $this->assertCount(4, $role->permissions);
        $this->assertContains('users.read', $role->permissions);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_update_custom_role(): void
    {
        // ARRANGE: Create a custom role
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'editor',
            'display_name' => 'Editor',
            'permissions' => ['users.read', 'applications.read'],
        ]);

        // ACT: Update role
        $updateData = [
            'display_name' => 'Senior Editor',
            'description' => 'Updated description',
            'permissions' => [
                'users.read',
                'users.update',
                'applications.read',
                'applications.update',
            ],
        ];

        $response = $this->actingAs($this->admin, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$role->id}", $updateData);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'display_name' => 'Senior Editor',
                    'description' => 'Updated description',
                ],
            ]);

        // ASSERT: Verify database update
        $role->refresh();
        $this->assertEquals('Senior Editor', $role->display_name);
        $this->assertCount(4, $role->permissions);
        $this->assertContains('users.update', $role->permissions);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_delete_custom_role(): void
    {
        // ARRANGE: Create a custom role with no users
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'temporary_role',
        ]);

        // ACT: Delete role
        $response = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$role->id}");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'Custom role deleted successfully',
            ]);

        // ASSERT: Verify soft delete
        $this->assertSoftDeleted('custom_roles', [
            'id' => $role->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_list_custom_roles(): void
    {
        // ARRANGE: Create multiple custom roles
        CustomRole::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        CustomRole::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
            'is_active' => false,
        ]);

        // ACT: List all custom roles
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles");

        // ASSERT: Verify response structure
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'display_name',
                        'description',
                        'permissions',
                        'is_active',
                        'user_count',
                    ],
                ],
            ]);

        // ASSERT: Verify all roles included
        $roles = $response->json('data');
        $this->assertGreaterThanOrEqual(7, count($roles));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_assign_role_to_user(): void
    {
        // ARRANGE: Create custom role and user
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'manager',
            'permissions' => ['users.read', 'users.update'],
        ]);

        $user = $this->createUser(['organization_id' => $this->organization->id]);

        // ACT: Assign role to user
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$role->id}/assign-users", [
                'user_ids' => [$user->id],
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'assigned_count' => 1,
                ],
            ]);

        // ASSERT: Verify role assignment
        $role->refresh();
        $this->assertTrue($role->users()->where('user_id', $user->id)->exists());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_remove_role_from_user(): void
    {
        // ARRANGE: Create role and assign to user
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $user = $this->createUser(['organization_id' => $this->organization->id]);
        $role->users()->attach($user->id);

        // ACT: Remove role from user
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$role->id}/remove-users", [
                'user_ids' => [$user->id],
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'removed_count' => 1,
                ],
            ]);

        // ASSERT: Verify role removed
        $role->refresh();
        $this->assertFalse($role->users()->where('user_id', $user->id)->exists());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_role_permissions_are_enforced(): void
    {
        // ARRANGE: Create role with limited permissions
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'limited_role',
            'permissions' => ['users.read'], // Can only read users
        ]);

        $user = $this->createUser(['organization_id' => $this->organization->id]);
        $role->users()->attach($user->id);

        // ACT: Attempt action not in permissions (users.delete)
        $targetUser = $this->createUser(['organization_id' => $this->organization->id]);
        $response = $this->actingAs($user, 'api')
            ->deleteJson("/api/v1/users/{$targetUser->id}");

        // ASSERT: Verify access denied
        $response->assertStatus(403);

        // ASSERT: Verify user was not deleted
        $this->assertDatabaseHas('users', [
            'id' => $targetUser->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_role_hierarchy_validation(): void
    {
        // ARRANGE: Create parent and child roles
        $parentRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'admin_role',
            'permissions' => [
                'users.read', 'users.create', 'users.update', 'users.delete',
                'applications.read', 'applications.create',
            ],
        ]);

        $childRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'user_role',
            'permissions' => ['users.read', 'applications.read'],
        ]);

        // ASSERT: Verify permission hierarchy
        $this->assertTrue($parentRole->hasPermission('users.delete'));
        $this->assertFalse($childRole->hasPermission('users.delete'));

        // ASSERT: Verify child has subset of parent permissions
        $childPermissions = $childRole->permissions;
        $parentPermissions = $parentRole->permissions;

        foreach ($childPermissions as $permission) {
            $this->assertContains($permission, $parentPermissions);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_duplicate_role_name_validation(): void
    {
        // ARRANGE: Create existing role
        CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'existing_role',
        ]);

        // ACT: Attempt to create duplicate role
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles", [
                'name' => 'existing_role', // Duplicate name
                'display_name' => 'Another Role',
                'permissions' => ['users.read'],
            ]);

        // ASSERT: Verify validation error
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_permission_inheritance_across_roles(): void
    {
        // ARRANGE: Create base role with permissions
        $baseRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'base_role',
            'permissions' => ['users.read', 'applications.read'],
        ]);

        // Create extended role with additional permissions
        $extendedRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'extended_role',
            'permissions' => [
                'users.read',
                'applications.read',
                'users.update', // Additional permission
                'applications.update', // Additional permission
            ],
        ]);

        // ASSERT: Verify base role has base permissions
        $this->assertTrue($baseRole->hasPermission('users.read'));
        $this->assertTrue($baseRole->hasPermission('applications.read'));
        $this->assertFalse($baseRole->hasPermission('users.update'));

        // ASSERT: Verify extended role has all permissions
        $this->assertTrue($extendedRole->hasPermission('users.read'));
        $this->assertTrue($extendedRole->hasPermission('applications.read'));
        $this->assertTrue($extendedRole->hasPermission('users.update'));
        $this->assertTrue($extendedRole->hasPermission('applications.update'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_cannot_delete_role_with_assigned_users(): void
    {
        // ARRANGE: Create role and assign to users
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => false,
        ]);

        $users = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        foreach ($users as $user) {
            $role->users()->attach($user->id);
        }

        // ACT: Attempt to delete role
        $response = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$role->id}");

        // ASSERT: Verify deletion prevented
        $response->assertStatus(400)
            ->assertJson([
                'error' => 'Cannot delete role with assigned users',
            ]);

        // ASSERT: Verify role still exists
        $this->assertDatabaseHas('custom_roles', [
            'id' => $role->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_system_roles_cannot_be_modified(): void
    {
        // ARRANGE: Create system role
        $systemRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'is_system' => true,
            'name' => 'system_admin',
        ]);

        // ACT: Attempt to update system role
        $updateResponse = $this->actingAs($this->admin, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$systemRole->id}", [
                'display_name' => 'Modified Name',
            ]);

        // ASSERT: Verify modification prevented
        $updateResponse->assertStatus(403);

        // ACT: Attempt to delete system role
        $deleteResponse = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$systemRole->id}");

        // ASSERT: Verify deletion prevented
        $deleteResponse->assertStatus(403);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_role_listing_includes_user_counts(): void
    {
        // ARRANGE: Create roles with different user counts
        $role1 = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'role_1',
        ]);

        $role2 = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'role_2',
        ]);

        // Assign users to role1
        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        foreach ($users as $user) {
            $role1->users()->attach($user->id);
        }

        // ACT: List roles
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles");

        // ASSERT: Verify user counts included
        $response->assertOk();
        $roles = $response->json('data');

        $role1Data = collect($roles)->firstWhere('id', $role1->id);
        $role2Data = collect($roles)->firstWhere('id', $role2->id);

        $this->assertEquals(5, $role1Data['user_count']);
        $this->assertEquals(0, $role2Data['user_count']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_roles_respect_organization_boundaries(): void
    {
        // ARRANGE: Create role in different organization
        $otherOrg = $this->createOrganization();
        $otherRole = CustomRole::factory()->create([
            'organization_id' => $otherOrg->id,
            'name' => 'other_org_role',
        ]);

        // ACT: Attempt to access other organization's role
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$otherRole->id}");

        // ASSERT: Verify access denied
        $response->assertNotFound();

        // ACT: List roles in current organization
        $listResponse = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles");

        // ASSERT: Verify other org's role not listed
        $roles = $listResponse->json('data');
        $roleIds = collect($roles)->pluck('id')->toArray();
        $this->assertNotContains($otherRole->id, $roleIds);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_clone_existing_role(): void
    {
        // ARRANGE: Create source role
        $sourceRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'source_role',
            'display_name' => 'Source Role',
            'permissions' => ['users.read', 'applications.read'],
        ]);

        // ACT: Clone role
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$sourceRole->id}/clone", [
                'name' => 'cloned_role',
                'display_name' => 'Cloned Role',
            ]);

        // ASSERT: Verify response
        $response->assertStatus(201);

        // ASSERT: Verify cloned role created with same permissions
        $clonedRole = CustomRole::where('name', 'cloned_role')
            ->where('organization_id', $this->organization->id)
            ->first();

        $this->assertNotNull($clonedRole);
        $this->assertEquals($sourceRole->permissions, $clonedRole->permissions);
        $this->assertEquals('Cloned Role', $clonedRole->display_name);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_role_permission_categories_are_grouped(): void
    {
        // ARRANGE: Create role with permissions from multiple categories
        $role = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'permissions' => [
                'users.read', 'users.create', // User category
                'applications.read', 'applications.update', // Application category
                'organization.read', // Organization category
            ],
        ]);

        // ACT: Get role details
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/custom-roles/{$role->id}");

        // ASSERT: Verify permissions grouped by category
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'permissions',
                    'permissions_grouped',
                ],
            ]);

        $grouped = $response->json('data.permissions_grouped');
        $this->assertArrayHasKey('users', $grouped);
        $this->assertArrayHasKey('applications', $grouped);
        $this->assertArrayHasKey('organization', $grouped);
        $this->assertCount(2, $grouped['users']); // users.read, users.create
    }
}
