<?php

namespace Tests\Unit\Services;

use App\Models\CustomRole;
use App\Models\Role;
use App\Services\UserRoleService;
use Illuminate\Database\Eloquent\Collection;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\TestCase;

class UserRoleServiceTest extends TestCase
{
    #[Test]
    public function it_denies_a_role_change_on_a_user_of_another_organization(): void
    {
        $organization = $this->createOrganization();
        $otherOrganization = $this->createOrganization();
        $caller = $this->createApiOrganizationOwner(['organization_id' => $organization->id]);
        $target = $this->createApiUser(['organization_id' => $otherOrganization->id]);
        $ownRole = $this->memberRole($organization->id);
        $foreignRole = $this->memberRole($otherOrganization->id);
        $service = app(UserRoleService::class);

        $this->assertNull($service->roleChangeDenial($caller, $this->createApiUser(['organization_id' => $organization->id]), new Collection([$ownRole])));
        $this->assertNotNull($service->roleChangeDenial($caller, $target, new Collection([$ownRole])));
        $this->assertNotNull($service->roleChangeDenial($caller, null, new Collection([$foreignRole])));
    }

    #[Test]
    public function it_exempts_super_admins_from_the_organization_match(): void
    {
        $otherOrganization = $this->createOrganization();
        $caller = $this->createApiSuperAdmin();
        $target = $this->createApiUser(['organization_id' => $otherOrganization->id]);

        $this->assertNull(app(UserRoleService::class)->roleChangeDenial($caller, $target, new Collection([$this->memberRole($otherOrganization->id)])));
    }

    #[Test]
    public function it_resolves_effective_permissions_in_the_users_organization_without_an_ambient_team(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        CustomRole::factory()->forOrganization($owner->organization)
            ->create(['permissions' => ['auth_logs.export']])
            ->assignToUser($owner);
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId(null);
        $owner = $owner->fresh();

        $names = app(UserRoleService::class)->effectivePermissionNames($owner);

        $this->assertContains('organizations.update', $names);
        $this->assertContains('users.delete', $names);
        $this->assertContains('auth_logs.export', $names);
        $this->assertNull($registrar->getPermissionsTeamId());
        $this->assertFalse($owner->relationLoaded('roles'));
    }

    #[Test]
    public function it_treats_a_super_admin_target_as_exceeding_every_other_caller(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $superAdmin = $this->createUser(['organization_id' => $owner->organization_id], 'Super Admin', 'web');
        $otherSuperAdmin = $this->createSuperAdmin();
        $member = $this->createUser(['organization_id' => $owner->organization_id], 'User', 'web');
        $service = app(UserRoleService::class);

        $this->assertTrue($service->exceedsPermissionsOf($owner, $superAdmin));
        $this->assertFalse($service->exceedsPermissionsOf($otherSuperAdmin, $superAdmin));
        $this->assertFalse($service->exceedsPermissionsOf($owner, $member));
    }

    private function memberRole(int $organizationId): Role
    {
        return Role::where('name', 'Organization Member')
            ->where('organization_id', $organizationId)
            ->where('guard_name', 'api')
            ->firstOrFail();
    }
}
