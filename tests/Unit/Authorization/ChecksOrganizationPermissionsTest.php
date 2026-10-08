<?php

namespace Tests\Unit\Authorization;

use App\Models\Organization;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ChecksOrganizationPermissionsTest extends TestCase
{
    #[Test]
    public function it_permits_a_super_admin_acting_on_another_organization(): void
    {
        $superAdmin = $this->createSuperAdmin();
        $otherOrganization = Organization::factory()->create();

        $this->assertNotNull($superAdmin->organization_id);
        $this->assertTrue($this->permits($superAdmin, 'organizations.update', $otherOrganization->id));
        $this->assertTrue($this->permits($superAdmin, 'organizations.update'));
    }

    #[Test]
    public function it_denies_a_missing_organization_id_when_one_is_required(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');

        $this->assertFalse($this->permits($admin, 'users.read'));
    }

    #[Test]
    public function it_denies_a_record_of_another_organization(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $otherOrganization = Organization::factory()->create();

        $this->assertFalse($this->permits($admin, 'users.read', $otherOrganization->id));
    }

    #[Test]
    public function it_denies_a_user_without_an_organization(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $organizationId = $admin->organization_id;
        $admin->update(['organization_id' => null]);

        $this->assertFalse($this->permits($admin, 'users.read', $organizationId));
        $this->assertFalse($this->permits($admin, 'users.read'));
        $this->assertFalse($this->permits($admin, 'users.read', null, false));
    }

    #[Test]
    public function it_checks_the_permission_within_the_users_organization(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');

        $this->assertTrue($this->permits($admin, 'users.read', $admin->organization_id));
        $this->assertFalse($this->permits($admin, 'organizations.update', $admin->organization_id));
    }

    #[Test]
    public function it_skips_the_organization_match_when_not_required(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $otherOrganization = Organization::factory()->create();

        $this->assertTrue($this->permits($admin, 'users.create', null, false));
        $this->assertTrue($this->permits($admin, 'users.create', $otherOrganization->id, false));
        $this->assertFalse($this->permits($admin, 'organizations.update', null, false));
    }

    private function permits(User $user, string $permission, ?int $organizationId = null, bool $requireOrganization = true): bool
    {
        $policy = new class
        {
            use ChecksOrganizationPermissions;

            public function check(User $user, string $permission, ?int $organizationId, bool $requireOrganization): bool
            {
                return $this->permits($user, $permission, $organizationId, $requireOrganization);
            }
        };

        return $policy->check($user, $permission, $organizationId, $requireOrganization);
    }
}
