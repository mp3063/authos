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

    private function ownerRole(int $organizationId, string $guard): Role
    {
        return Role::where('name', 'Organization Owner')
            ->where('organization_id', $organizationId)
            ->where('guard_name', $guard)
            ->firstOrFail();
    }
}
