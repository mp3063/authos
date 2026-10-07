<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Filament\Resources\UserResource\Pages\EditUser;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class UserRoleEscalationTest extends IntegrationTestCase
{
    private Organization $organization;

    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->admin = $this->createOrganizationAdmin(['organization_id' => $this->organization->id]);
        $this->actingAs($this->admin);
        app(PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);
    }

    #[Test]
    public function an_organization_admin_cannot_give_themselves_the_super_admin_role(): void
    {
        $this->createSuperAdmin();
        $superAdminRole = Role::where('name', 'Super Admin')->whereNull('organization_id')->firstOrFail();

        Livewire::test(EditUser::class, ['record' => $this->admin->getRouteKey()])
            ->fillForm(['roles' => [$superAdminRole->id]])
            ->call('save')
            ->assertHasFormErrors(['roles']);

        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $this->admin->id, 'role_id' => $superAdminRole->id]);
        $this->assertFalse($this->admin->fresh()->isSuperAdmin());
    }

    #[Test]
    public function an_organization_admin_assigns_a_role_within_their_permissions_tied_to_the_organization(): void
    {
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $memberRole = $this->webRole('Organization Member');

        Livewire::test(EditUser::class, ['record' => $member->getRouteKey()])
            ->fillForm(['roles' => [$memberRole->id]])
            ->call('save')
            ->assertHasNoFormErrors();

        $this->assertDatabaseHas('model_has_roles', [
            'model_id' => $member->id,
            'role_id' => $memberRole->id,
            'organization_id' => $this->organization->id,
        ]);
    }

    #[Test]
    public function an_organization_admin_cannot_assign_a_role_with_permissions_they_lack(): void
    {
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $ownerRole = $this->webRole('Organization Owner');

        Livewire::test(EditUser::class, ['record' => $member->getRouteKey()])
            ->fillForm(['roles' => [$ownerRole->id]])
            ->call('save')
            ->assertHasFormErrors(['roles']);

        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $member->id, 'role_id' => $ownerRole->id]);
    }

    #[Test]
    public function the_direct_permissions_field_is_hidden_from_organization_admins(): void
    {
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        Livewire::test(EditUser::class, ['record' => $member->getRouteKey()])
            ->assertFormFieldIsHidden('permissions');
    }

    #[Test]
    public function organization_admins_cannot_assign_permissions_to_roles(): void
    {
        $permission = Permission::where('organization_id', $this->organization->id)->firstOrFail();

        Livewire::test(ListRoles::class)
            ->assertTableBulkActionHidden('assign_permission');

        Livewire::test(ListPermissions::class)
            ->assertTableActionHidden('assign_to_role', $permission)
            ->assertTableBulkActionHidden('assign_to_role');
    }

    #[Test]
    public function organization_owners_cannot_change_a_roles_permissions(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner');
        $this->actingAs($owner);

        Livewire::test(EditRole::class, ['record' => $this->webRole('Organization Member')->getRouteKey()])
            ->assertFormFieldIsDisabled('permissions');
    }

    private function webRole(string $name): Role
    {
        return Role::where('name', $name)
            ->where('organization_id', $this->organization->id)
            ->where('guard_name', 'web')
            ->firstOrFail();
    }
}
