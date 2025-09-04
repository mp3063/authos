<?php

namespace Tests\Unit\Models;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class CustomRoleTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization = Organization::factory()->create();
    }

    public function test_custom_role_belongs_to_organization(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->assertInstanceOf(Organization::class, $role->organization);
        $this->assertEquals($this->organization->id, $role->organization->id);
    }

    public function test_custom_role_has_many_users(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        $user1 = User::factory()->forOrganization($this->organization)->create();
        $user2 = User::factory()->forOrganization($this->organization)->create();

        $role->users()->attach([$user1->id, $user2->id]);

        $this->assertCount(2, $role->users);
        $this->assertTrue($role->users->contains($user1));
        $this->assertTrue($role->users->contains($user2));
    }

    public function test_active_scope_filters_active_roles(): void
    {
        // Create active role
        $activeRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create(['is_active' => true]);

        // Create inactive role
        $inactiveRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->inactive()
            ->create();

        $activeRoles = CustomRole::active()->get();

        $this->assertTrue($activeRoles->contains($activeRole));
        $this->assertFalse($activeRoles->contains($inactiveRole));
    }

    public function test_for_organization_scope_filters_by_organization(): void
    {
        $otherOrganization = Organization::factory()->create();

        // Create role for our organization
        $ourRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        // Create role for other organization
        $otherRole = CustomRole::factory()
            ->forOrganization($otherOrganization)
            ->create();

        $organizationRoles = CustomRole::forOrganization($this->organization->id)->get();

        $this->assertTrue($organizationRoles->contains($ourRole));
        $this->assertFalse($organizationRoles->contains($otherRole));
    }

    public function test_default_scope_filters_default_roles(): void
    {
        // Create default role
        $defaultRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->default()
            ->create(['name' => 'Default Role ' . uniqid()]);

        // Create non-default role
        $regularRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create([
                'name' => 'Regular Role ' . uniqid(),
                'is_default' => false
            ]);

        $defaultRoles = CustomRole::default()->get();

        $this->assertTrue($defaultRoles->contains($defaultRole));
        $this->assertFalse($defaultRoles->contains($regularRole));
    }

    public function test_has_permission_checks_if_permission_exists(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view', 'users.create', 'reports.view'])
            ->create();

        $this->assertTrue($role->hasPermission('users.view'));
        $this->assertTrue($role->hasPermission('users.create'));
        $this->assertFalse($role->hasPermission('users.delete'));
    }

    public function test_add_permission_adds_permission_to_role(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view'])
            ->create();

        $role->addPermission('users.create');

        $this->assertTrue($role->hasPermission('users.create'));
        $this->assertContains('users.create', $role->permissions);
    }

    public function test_add_permission_does_not_duplicate_existing_permission(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view'])
            ->create();

        $initialCount = count($role->permissions);
        $role->addPermission('users.view'); // Try to add existing permission

        $this->assertEquals($initialCount, count($role->permissions));
    }

    public function test_remove_permission_removes_permission_from_role(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view', 'users.create', 'users.delete'])
            ->create();

        $role->removePermission('users.delete');

        $this->assertFalse($role->hasPermission('users.delete'));
        $this->assertNotContains('users.delete', $role->permissions);
        $this->assertTrue($role->hasPermission('users.view')); // Other permissions remain
    }

    public function test_add_permissions_adds_multiple_permissions(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view'])
            ->create();

        $newPermissions = ['users.create', 'users.edit', 'reports.view'];
        $role->addPermissions($newPermissions);

        foreach ($newPermissions as $permission) {
            $this->assertTrue($role->hasPermission($permission));
        }
    }

    public function test_remove_permissions_removes_multiple_permissions(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view', 'users.create', 'users.edit', 'users.delete'])
            ->create();

        $permissionsToRemove = ['users.edit', 'users.delete'];
        $role->removePermissions($permissionsToRemove);

        foreach ($permissionsToRemove as $permission) {
            $this->assertFalse($role->hasPermission($permission));
        }
        
        // Check remaining permissions
        $this->assertTrue($role->hasPermission('users.view'));
        $this->assertTrue($role->hasPermission('users.create'));
    }

    public function test_sync_permissions_replaces_all_permissions(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view', 'users.create', 'applications.view'])
            ->create();

        $newPermissions = ['reports.view', 'settings.edit'];
        $role->syncPermissions($newPermissions);

        // Old permissions should be gone
        $this->assertFalse($role->hasPermission('users.view'));
        $this->assertFalse($role->hasPermission('applications.view'));
        
        // New permissions should exist
        $this->assertTrue($role->hasPermission('reports.view'));
        $this->assertTrue($role->hasPermission('settings.edit'));
    }

    public function test_get_permission_count_returns_correct_count(): void
    {
        $permissions = ['users.view', 'users.create', 'reports.view', 'settings.edit'];
        
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions($permissions)
            ->create();

        $this->assertEquals(4, $role->getPermissionCount());
    }

    public function test_is_admin_role_identifies_admin_roles(): void
    {
        $adminRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->admin()
            ->create();

        $regularRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->readOnly()
            ->create();

        $this->assertTrue($adminRole->isAdminRole());
        $this->assertFalse($regularRole->isAdminRole());
    }

    public function test_can_manage_users_checks_user_management_permissions(): void
    {
        $roleWithUserPermissions = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view', 'users.create', 'users.edit'])
            ->create();

        $roleWithoutUserPermissions = CustomRole::factory()
            ->forOrganization($this->organization)
            ->readOnly()
            ->create();

        $this->assertTrue($roleWithUserPermissions->canManageUsers());
        $this->assertFalse($roleWithoutUserPermissions->canManageUsers());
    }

    public function test_can_manage_applications_checks_application_permissions(): void
    {
        $roleWithAppPermissions = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['applications.view', 'applications.create', 'applications.edit'])
            ->create();

        $roleWithoutAppPermissions = CustomRole::factory()
            ->forOrganization($this->organization)
            ->readOnly()
            ->create();

        $this->assertTrue($roleWithAppPermissions->canManageApplications());
        $this->assertFalse($roleWithoutAppPermissions->canManageApplications());
    }

    public function test_assign_to_user_creates_user_role_relationship(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        $user = User::factory()->forOrganization($this->organization)->create();

        $role->assignToUser($user->id);

        $this->assertTrue($role->users->contains($user));
    }

    public function test_unassign_from_user_removes_user_role_relationship(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        $user = User::factory()->forOrganization($this->organization)->create();

        // First assign the role
        $role->users()->attach($user->id);
        $this->assertTrue($role->users->contains($user));

        // Then unassign
        $role->unassignFromUser($user->id);
        $role->load('users'); // Reload the relationship

        $this->assertFalse($role->users->contains($user));
    }

    public function test_get_user_count_returns_assigned_user_count(): void
    {
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        $user1 = User::factory()->forOrganization($this->organization)->create();
        $user2 = User::factory()->forOrganization($this->organization)->create();
        $user3 = User::factory()->forOrganization($this->organization)->create();

        $role->users()->attach([$user1->id, $user2->id, $user3->id]);

        $this->assertEquals(3, $role->getUserCount());
    }

    public function test_clone_role_creates_copy_with_new_name(): void
    {
        $originalRole = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions(['users.view', 'reports.view'])
            ->create(['name' => 'Original Role']);

        $clonedRole = $originalRole->cloneRole('Cloned Role');

        $this->assertNotEquals($originalRole->id, $clonedRole->id);
        $this->assertEquals('Cloned Role', $clonedRole->name);
        $this->assertEquals($originalRole->permissions, $clonedRole->permissions);
        $this->assertEquals($originalRole->organization_id, $clonedRole->organization_id);
        $this->assertFalse($clonedRole->is_default); // Clone should not be default
    }

    public function test_permissions_are_cast_to_array(): void
    {
        $permissions = ['users.view', 'users.create', 'reports.view'];
        
        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create(['permissions' => $permissions]);

        $this->assertIsArray($role->permissions);
        $this->assertEquals($permissions, $role->permissions);
    }

    public function test_role_has_correct_fillable_attributes(): void
    {
        $fillable = [
            'name', 'display_name', 'description', 'organization_id',
            'permissions', 'is_active', 'is_default'
        ];

        $role = new CustomRole();

        $this->assertEquals($fillable, $role->getFillable());
    }

    public function test_get_grouped_permissions_groups_permissions_by_category(): void
    {
        $permissions = [
            'users.view', 'users.create', 'users.edit',
            'applications.view', 'applications.create',
            'reports.view', 'settings.edit'
        ];

        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->withPermissions($permissions)
            ->create();

        $grouped = $role->getGroupedPermissions();

        $this->assertArrayHasKey('users', $grouped);
        $this->assertArrayHasKey('applications', $grouped);
        $this->assertArrayHasKey('reports', $grouped);
        $this->assertArrayHasKey('settings', $grouped);

        $this->assertCount(3, $grouped['users']); // view, create, edit
        $this->assertCount(2, $grouped['applications']); // view, create
        $this->assertCount(1, $grouped['reports']); // view
        $this->assertCount(1, $grouped['settings']); // edit
    }
}