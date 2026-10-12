<?php

namespace Tests\Integration\Organizations;

use App\Models\Role;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Permission;
use Tests\Integration\IntegrationTestCase;

class OrganizationDefaultRolesTest extends IntegrationTestCase
{
    #[Test]
    public function a_new_organizations_owner_role_can_assign_roles(): void
    {
        $organization = $this->createOrganization();

        foreach (['web', 'api'] as $guard) {
            $this->assertTrue($this->ownerRole($organization->id, $guard)->hasPermissionTo('roles.assign', $guard));
        }
    }

    #[Test]
    public function the_backfill_grants_roles_assign_to_existing_owner_roles(): void
    {
        $organization = $this->createOrganization();
        foreach (['web', 'api'] as $guard) {
            $ownerRole = $this->ownerRole($organization->id, $guard);
            $ownerRole->permissions()->detach(
                Permission::where('name', 'roles.assign')->where('guard_name', $guard)->where('organization_id', $organization->id)->pluck('id')
            );
            $ownerRole->forgetCachedPermissions();
        }

        (require database_path('migrations/2026_10_07_173604_grant_roles_assign_to_organization_owners.php'))->up();

        foreach (['web', 'api'] as $guard) {
            $this->assertTrue($this->ownerRole($organization->id, $guard)->fresh()->hasPermissionTo('roles.assign', $guard));
        }
    }

    #[Test]
    public function a_new_organizations_owner_and_admin_roles_grant_admin_access(): void
    {
        $organization = $this->createOrganization();

        foreach (['Organization Owner', 'Organization Admin'] as $roleName) {
            foreach (['web', 'api'] as $guard) {
                $this->assertTrue($this->organizationRole($organization->id, $guard, $roleName)->permissions()->where('name', 'admin.access')->exists());
            }
        }
    }

    #[Test]
    public function the_backfill_grants_admin_access_to_existing_owner_and_admin_roles(): void
    {
        $organization = $this->createOrganization();
        foreach (['Organization Owner', 'Organization Admin'] as $roleName) {
            foreach (['web', 'api'] as $guard) {
                $role = $this->organizationRole($organization->id, $guard, $roleName);
                $role->permissions()->detach(
                    Permission::where('name', 'admin.access')->where('guard_name', $guard)->where('organization_id', $organization->id)->pluck('id')
                );
                $role->forgetCachedPermissions();
            }
        }

        $backfill = require database_path('migrations/2026_10_12_213618_grant_admin_access_to_organization_owners_and_admins.php');
        $backfill->up();
        $backfill->up();

        foreach (['Organization Owner', 'Organization Admin'] as $roleName) {
            foreach (['web', 'api'] as $guard) {
                $role = $this->organizationRole($organization->id, $guard, $roleName)->fresh();
                $this->assertSame(1, $role->permissions()->where('name', 'admin.access')->count());
            }
        }
        $this->assertFalse($this->organizationRole($organization->id, 'web', 'Organization Member')->permissions()->where('name', 'admin.access')->exists());
    }

    private function ownerRole(int $organizationId, string $guard): Role
    {
        return $this->organizationRole($organizationId, $guard, 'Organization Owner');
    }

    private function organizationRole(int $organizationId, string $guard, string $name): Role
    {
        return Role::where('name', $name)
            ->where('organization_id', $organizationId)
            ->where('guard_name', $guard)
            ->firstOrFail();
    }
}
