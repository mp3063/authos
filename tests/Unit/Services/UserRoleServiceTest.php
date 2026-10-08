<?php

namespace Tests\Unit\Services;

use App\Models\Role;
use App\Services\UserRoleService;
use Illuminate\Database\Eloquent\Collection;
use PHPUnit\Framework\Attributes\Test;
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

    private function memberRole(int $organizationId): Role
    {
        return Role::where('name', 'Organization Member')
            ->where('organization_id', $organizationId)
            ->where('guard_name', 'api')
            ->firstOrFail();
    }
}
