<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\AccountLockoutResource\Pages\ListAccountLockouts;
use App\Filament\Resources\PermissionResource\Pages\EditPermission;
use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Models\AccountLockout;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class StrictAuthorizationTest extends IntegrationTestCase
{
    #[Test]
    public function it_denies_an_ability_the_policy_does_not_define(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        AccountLockout::factory()->create(['user_id' => $owner->id]);
        $policyWithoutBulkDelete = new class
        {
            public function viewAny(User $user): bool
            {
                return true;
            }

            public function view(User $user): bool
            {
                return true;
            }
        };
        app()->instance($policyWithoutBulkDelete::class, $policyWithoutBulkDelete);
        Gate::policy(AccountLockout::class, $policyWithoutBulkDelete::class);
        $this->actingAs($owner);

        $this->expectExceptionMessage('Strict authorization mode is enabled, but no [deleteAny()] method was found');

        Livewire::test(ListAccountLockouts::class)->assertTableBulkActionHidden('delete');
    }

    #[Test]
    public function a_super_admin_cannot_delete_the_super_admin_role_in_the_panel(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $superAdminRole = Role::where('name', 'Super Admin')->where('guard_name', 'web')->whereNull('organization_id')->firstOrFail();
        $deletableRole = Role::create(['name' => 'Temporary Role', 'guard_name' => 'web']);

        Livewire::test(ListRoles::class)
            ->assertTableActionHidden('delete', $superAdminRole)
            ->assertTableActionVisible('delete', $deletableRole);

        Livewire::test(EditRole::class, ['record' => $superAdminRole->getRouteKey()])
            ->assertActionHidden('delete');
    }

    #[Test]
    public function a_super_admin_cannot_delete_the_admin_access_permission_in_the_panel(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $adminAccess = Permission::where('name', 'admin.access')->where('guard_name', 'web')->whereNull('organization_id')->firstOrFail();
        $deletablePermission = Permission::create(['name' => 'temporary.permission', 'guard_name' => 'web']);

        Livewire::test(ListPermissions::class)
            ->assertTableActionHidden('delete', $adminAccess)
            ->assertTableActionVisible('delete', $deletablePermission);

        Livewire::test(EditPermission::class, ['record' => $adminAccess->getRouteKey()])
            ->assertActionHidden('delete');
    }
}
