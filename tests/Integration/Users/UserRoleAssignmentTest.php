<?php

namespace Tests\Integration\Users;

use App\Models\Role;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class UserRoleAssignmentTest extends IntegrationTestCase
{
    #[Test]
    public function an_organization_admin_cannot_assign_the_super_admin_role_with_422(): void
    {
        $this->createApiSuperAdmin();
        $superAdminRole = Role::where('name', 'Super Admin')->whereNull('organization_id')->firstOrFail();
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson("/api/v1/users/{$member->id}/roles", ['role_id' => $superAdminRole->id]);

        $response->assertUnprocessable()->assertJsonValidationErrors(['role_id' => 'The selected role id is invalid.']);
        $this->assertFalse($member->fresh()->isSuperAdmin());
    }

    #[Test]
    public function an_organization_admin_cannot_assign_another_organizations_role_with_422(): void
    {
        $foreignAdmin = $this->createApiOrganizationAdmin();
        $foreignRole = Role::where('name', 'Organization Admin')
            ->where('organization_id', $foreignAdmin->organization_id)
            ->firstOrFail();
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson("/api/v1/users/{$member->id}/roles", ['role_id' => $foreignRole->id]);

        $response->assertUnprocessable()->assertJsonValidationErrors(['role_id' => 'The selected role id is invalid.']);
        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $member->id, 'role_id' => $foreignRole->id]);
    }

    #[Test]
    public function an_organization_admin_cannot_sync_the_super_admin_role_with_422(): void
    {
        $this->createApiSuperAdmin();
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$member->id}/roles", ['roles' => ['Super Admin']]);

        $response->assertUnprocessable()->assertJsonValidationErrors(['roles.0' => 'The selected roles.0 is invalid.']);
        $this->assertFalse($member->fresh()->isSuperAdmin());
    }

    #[Test]
    public function a_user_without_an_organization_cannot_assign_themselves_a_global_role_with_422(): void
    {
        $this->createApiSuperAdmin();
        $superAdminRole = Role::where('name', 'Super Admin')->whereNull('organization_id')->firstOrFail();
        $roleAssigner = Role::create(['name' => 'Platform Support', 'guard_name' => 'api', 'organization_id' => null]);
        $roleAssigner->givePermissionTo(Permission::firstOrCreate(['name' => 'roles.assign', 'guard_name' => 'api']));
        $orphan = User::factory()->create(['organization_id' => null]);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $orphan->assignRole($roleAssigner);

        $response = $this->actingAsApiUserWithToken($orphan)
            ->postJson("/api/v1/users/{$orphan->id}/roles", ['role_id' => $superAdminRole->id]);

        $response->assertUnprocessable()->assertJsonValidationErrors(['role_id' => 'The selected role id is invalid.']);
        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $orphan->id, 'role_id' => $superAdminRole->id]);
    }

    #[Test]
    public function a_super_admin_can_assign_the_super_admin_role(): void
    {
        $superAdmin = $this->createApiSuperAdmin();
        $superAdminRole = Role::where('name', 'Super Admin')->whereNull('organization_id')->firstOrFail();
        $member = $this->createApiUser();

        $response = $this->actingAsApiUserWithToken($superAdmin)
            ->postJson("/api/v1/users/{$member->id}/roles", ['role_id' => $superAdminRole->id]);

        $response->assertCreated();
        $this->assertDatabaseHas('model_has_roles', ['model_id' => $member->id, 'role_id' => $superAdminRole->id]);
    }

    #[Test]
    public function an_organization_admin_can_assign_a_role_of_their_own_organization(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);
        $ownRole = Role::where('name', 'Organization Admin')
            ->where('organization_id', $admin->organization_id)
            ->firstOrFail();

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson("/api/v1/users/{$member->id}/roles", ['role_id' => $ownRole->id]);

        $response->assertCreated();
        $this->assertDatabaseHas('model_has_roles', ['model_id' => $member->id, 'role_id' => $ownRole->id]);
    }
}
