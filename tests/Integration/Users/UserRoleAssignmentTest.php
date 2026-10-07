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

    #[Test]
    public function an_organization_admin_cannot_promote_themselves_to_organization_owner_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $ownerRole = $this->apiRole('Organization Owner', $admin->organization_id);

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson("/api/v1/users/{$admin->id}/roles", ['role_id' => $ownerRole->id]);

        $response->assertForbidden();
        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $admin->id, 'role_id' => $ownerRole->id]);
    }

    #[Test]
    public function an_organization_admin_cannot_assign_a_role_with_permissions_they_lack_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);
        $ownerRole = $this->apiRole('Organization Owner', $admin->organization_id);

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson("/api/v1/users/{$member->id}/roles", ['role_id' => $ownerRole->id]);

        $response->assertForbidden();
        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $member->id, 'role_id' => $ownerRole->id]);
    }

    #[Test]
    public function an_organization_admin_cannot_sync_their_own_roles_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $this->apiRole('Organization Owner', $admin->organization_id);

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$admin->id}/roles", ['roles' => ['Organization Admin', 'Organization Owner']]);

        $response->assertForbidden();
        $this->assertFalse($admin->fresh()->roles()->where('name', 'Organization Owner')->exists());
    }

    #[Test]
    public function an_organization_admin_cannot_demote_an_organization_owner_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $owner = $this->createUser(['organization_id' => $admin->organization_id], 'Organization Owner', 'api');
        $ownerRole = $this->apiRole('Organization Owner', $admin->organization_id);
        $this->apiRole('User', $admin->organization_id);

        $sync = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$owner->id}/roles", ['roles' => ['User']]);
        $remove = $this->actingAsApiUserWithToken($admin)
            ->deleteJson("/api/v1/users/{$owner->id}/roles/{$ownerRole->id}");

        $sync->assertForbidden();
        $remove->assertForbidden();
        $this->assertDatabaseHas('model_has_roles', ['model_id' => $owner->id, 'role_id' => $ownerRole->id]);
    }

    #[Test]
    public function an_organization_admin_can_replace_a_members_roles_with_api_roles_of_their_organization(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createUser(['organization_id' => $admin->organization_id], 'User', 'api');
        $userRole = $member->roles()->firstOrFail();
        $adminRole = Role::where('name', 'Organization Admin')
            ->where('organization_id', $admin->organization_id)
            ->where('guard_name', 'api')
            ->firstOrFail();

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$member->id}/roles", ['roles' => ['Organization Admin']]);

        $response->assertOk();
        $this->assertSame([$adminRole->id], $member->fresh()->roles()->pluck('roles.id')->all());
        $this->assertDatabaseMissing('model_has_roles', ['model_id' => $member->id, 'role_id' => $userRole->id]);
    }

    #[Test]
    public function an_organization_admin_cannot_create_a_user_in_another_organization_with_422(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $otherOrganization = $this->createOrganization();

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson('/api/v1/users', $this->newUserPayload($otherOrganization->id));

        $response->assertUnprocessable();
        $this->assertDatabaseMissing('users', ['email' => 'new.user@example.com']);
    }

    #[Test]
    public function an_organization_admin_cannot_create_a_user_with_the_super_admin_role_with_422(): void
    {
        $this->createApiSuperAdmin();
        $admin = $this->createApiOrganizationAdmin();

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson('/api/v1/users', $this->newUserPayload($admin->organization_id, ['Super Admin']));

        $response->assertUnprocessable();
        $this->assertDatabaseMissing('users', ['email' => 'new.user@example.com']);
    }

    #[Test]
    public function an_organization_admin_cannot_create_a_user_with_a_role_exceeding_their_permissions_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $this->apiRole('Organization Owner', $admin->organization_id);

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson('/api/v1/users', $this->newUserPayload($admin->organization_id, ['Organization Owner']));

        $response->assertForbidden();
        $this->assertDatabaseMissing('users', ['email' => 'new.user@example.com']);
    }

    #[Test]
    public function an_organization_admin_creates_a_user_with_the_api_role_of_their_organization(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $userRole = $this->apiRole('User', $admin->organization_id);

        $response = $this->actingAsApiUserWithToken($admin)
            ->postJson('/api/v1/users', $this->newUserPayload($admin->organization_id, ['User']));

        $response->assertCreated();
        $created = User::where('email', 'new.user@example.com')->firstOrFail();
        $this->assertSame([$userRole->id], $created->roles()->pluck('roles.id')->all());
    }

    /**
     * @param  list<string>|null  $roles
     * @return array<string, mixed>
     */
    private function newUserPayload(int $organizationId, ?array $roles = null): array
    {
        return array_filter([
            'name' => 'New User',
            'email' => 'new.user@example.com',
            'password' => 'TestP@ssw0rd!2024_'.uniqid(),
            'organization_id' => $organizationId,
            'roles' => $roles,
        ], fn ($value) => $value !== null);
    }

    private function apiRole(string $name, int $organizationId): Role
    {
        $this->setupRoleWithPermissions($name, 'api', $organizationId);

        return Role::where('name', $name)
            ->where('organization_id', $organizationId)
            ->where('guard_name', 'api')
            ->firstOrFail();
    }
}
