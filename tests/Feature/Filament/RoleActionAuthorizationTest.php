<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\CustomRoleResource\Pages\ListCustomRoles;
use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Filament\Resources\RoleResource\RelationManagers\PermissionsRelationManager;
use App\Filament\Resources\RoleResource\RelationManagers\UsersRelationManager;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\Permission;
use App\Models\Role;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class RoleActionAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    private function actingAsOwner(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Owner'));
    }

    #[Test]
    public function it_hides_and_forbids_duplicate_for_a_role_without_the_permission(): void
    {
        $this->actingAsOwner();
        $role = Role::where('organization_id', $this->organization->id)->where('guard_name', 'web')->firstOrFail();
        $before = Role::count();

        $component = Livewire::test(ListRoles::class)->assertTableActionHidden('duplicate', $role);
        $this->forceTableAction($component, 'duplicate', $role, ['name' => 'Copied Role']);

        $this->assertSame($before, Role::count());
    }

    #[Test]
    public function a_super_admin_can_duplicate_a_role(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $role = Role::create(['name' => 'Source Role', 'guard_name' => 'web']);

        Livewire::test(ListRoles::class)
            ->assertTableActionVisible('duplicate', $role)
            ->callTableAction('duplicate', $role, ['name' => 'Copied Role']);

        $this->assertDatabaseHas('roles', ['name' => 'Copied Role']);
    }

    #[Test]
    public function it_hides_and_forbids_assign_permission_for_a_role_without_the_permission(): void
    {
        $this->actingAsOwner();

        Livewire::test(ListRoles::class)->assertTableBulkActionHidden('assign_permission');
    }

    #[Test]
    public function it_hides_and_forbids_assign_to_role_for_a_role_without_the_permission(): void
    {
        $this->actingAsOwner();
        $permission = Permission::where('organization_id', $this->organization->id)->where('guard_name', 'web')->firstOrFail();

        $component = Livewire::test(ListPermissions::class)
            ->assertTableActionHidden('assign_to_role', $permission)
            ->assertTableBulkActionHidden('assign_to_role');
        $before = $permission->roles()->count();
        $role = Role::where('organization_id', $this->organization->id)->where('guard_name', 'web')->whereDoesntHave('permissions', fn ($q) => $q->whereKey($permission->id))->firstOrFail();
        $this->forceTableAction($component, 'assign_to_role', $permission, ['role' => $role->id]);

        $this->assertSame($before, $permission->roles()->count());
    }

    #[Test]
    public function it_hides_and_forbids_clone_activate_and_deactivate_for_a_role_without_the_permission(): void
    {
        $this->actingAsOwner();
        $customRole = CustomRole::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true]);
        $before = CustomRole::count();

        $component = Livewire::test(ListCustomRoles::class)
            ->assertTableActionHidden('clone', $customRole)
            ->assertTableBulkActionHidden('activate')
            ->assertTableBulkActionHidden('deactivate');
        $this->forceTableAction($component, 'clone', $customRole, ['new_name' => 'Cloned']);

        $this->assertSame($before, CustomRole::count());
    }

    #[Test]
    public function a_super_admin_bulk_deleting_roles_keeps_the_protected_ones(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $protected = Role::where('name', 'Super Admin')->where('guard_name', 'web')->whereNull('organization_id')->firstOrFail();
        $deletable = Role::create(['name' => 'Temporary Role', 'guard_name' => 'web']);

        Livewire::test(ListRoles::class)
            ->callTableBulkAction('delete', [$protected, $deletable]);

        $this->assertNotNull(Role::find($protected->id));
        $this->assertNull(Role::find($deletable->id));
    }

    #[Test]
    public function a_super_admin_bulk_deleting_permissions_keeps_the_protected_ones(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $protected = Permission::where('name', 'admin.access')->where('guard_name', 'web')->whereNull('organization_id')->firstOrFail();
        $deletable = Permission::create(['name' => 'temporary.permission', 'guard_name' => 'web']);

        Livewire::test(ListPermissions::class)
            ->callTableBulkAction('delete', [$protected, $deletable]);

        $this->assertNotNull(Permission::find($protected->id));
        $this->assertNull(Permission::find($deletable->id));
    }

    #[Test]
    public function it_hides_and_forbids_attach_and_detach_on_role_relations_for_a_role_without_the_permission(): void
    {
        $this->actingAsOwner();
        $role = Role::where('organization_id', $this->organization->id)->where('guard_name', 'web')->firstOrFail();
        $permission = $role->permissions()->firstOrFail();

        $component = Livewire::test(PermissionsRelationManager::class, ['ownerRecord' => $role, 'pageClass' => EditRole::class])
            ->assertTableActionHidden('attach')
            ->assertTableActionHidden('detach', $permission)
            ->assertTableBulkActionHidden('detach');
        $this->forceTableAction($component, 'detach', $permission);

        Livewire::test(UsersRelationManager::class, ['ownerRecord' => $role, 'pageClass' => EditRole::class])
            ->assertTableActionHidden('attach')
            ->assertTableBulkActionHidden('detach');

        $this->assertTrue($role->permissions()->whereKey($permission->id)->exists());
    }

    #[Test]
    public function a_super_admin_can_detach_a_permission_from_a_role(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $role = Role::where('organization_id', $this->organization->id)->where('guard_name', 'web')->firstOrFail();
        $permission = $role->permissions()->firstOrFail();

        Livewire::test(PermissionsRelationManager::class, ['ownerRecord' => $role, 'pageClass' => EditRole::class])
            ->assertTableActionVisible('attach')
            ->callTableAction('detach', $permission);

        $this->assertFalse($role->permissions()->whereKey($permission->id)->exists());
    }
}
