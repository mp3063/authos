<?php

namespace Tests\Unit\Policies;

use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Models\Role;
use App\Models\User;
use App\Services\UserRoleService;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\TestCase;

class UserAndOrganizationPolicyMatrixTest extends TestCase
{
    private const RECORDLESS_ABILITIES = ['viewAny', 'create', 'deleteAny'];

    #[Test]
    #[DataProvider('userMatrix')]
    public function it_applies_the_matrix_to_users(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, User::class,
            fn (int $organizationId) => $this->createUser(['organization_id' => $organizationId], 'User', 'web'), $sameOrg);
    }

    #[Test]
    #[DataProvider('organizationMatrix')]
    public function it_applies_the_matrix_to_organizations(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, Organization::class,
            fn (int $organizationId) => Organization::findOrFail($organizationId), $sameOrg);
    }

    #[Test]
    #[DataProvider('organizationBrandingMatrix')]
    public function it_applies_the_matrix_to_organization_brandings(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, OrganizationBranding::class,
            fn (int $organizationId) => OrganizationBranding::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('invitationMatrix')]
    public function it_applies_the_matrix_to_invitations(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, Invitation::class,
            fn (int $organizationId) => Invitation::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    public function it_lets_a_plain_member_view_and_update_themselves_but_never_delete_themselves(): void
    {
        $member = $this->createUser([], 'User', 'web');
        $owner = $this->createUser([], 'Organization Owner', 'web');

        $this->assertTrue(Gate::forUser($member)->allows('view', $member));
        $this->assertTrue(Gate::forUser($member)->allows('update', $member));
        $this->assertFalse(Gate::forUser($member)->allows('delete', $member));
        $this->assertFalse(Gate::forUser($owner)->allows('delete', $owner));
    }

    #[Test]
    public function it_denies_updating_or_deleting_a_user_whose_permissions_exceed_the_callers(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $customRole = CustomRole::factory()->forOrganization($admin->organization)->create(['permissions' => ['users.delete']]);
        $customRole->assignToUser($admin);
        $owner = $this->createUser(['organization_id' => $admin->organization_id], 'Organization Owner', 'web');
        $peerAdmin = $this->createUser(['organization_id' => $admin->organization_id], 'Organization Admin', 'web');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $admin = $admin->fresh();

        $this->assertFalse(Gate::forUser($admin)->allows('update', $owner->fresh()));
        $this->assertFalse(Gate::forUser($admin)->allows('delete', $owner));
        $this->assertTrue(Gate::forUser($admin)->allows('update', $peerAdmin));
        $this->assertTrue(Gate::forUser($admin)->allows('delete', $peerAdmin));
        $this->assertNull(app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    #[Test]
    public function it_denies_an_owner_updating_or_deleting_a_super_admin_of_their_organization(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $superAdmin = $this->createUser(['organization_id' => $owner->organization_id], 'Super Admin', 'web');

        $this->assertFalse(Gate::forUser($owner)->allows('update', $superAdmin));
        $this->assertFalse(Gate::forUser($owner)->allows('delete', $superAdmin));
    }

    #[Test]
    public function it_checks_a_target_in_its_organization_whatever_the_ambient_team(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $member = $this->createUser(['organization_id' => $admin->organization_id], 'User', 'web');
        $member->setRelation('roles', Role::whereKey(app(UserRoleService::class)->assignedRoleIds($member))->get());
        $otherOrganization = Organization::factory()->create();
        app(PermissionRegistrar::class)->setPermissionsTeamId($otherOrganization->id);

        $this->assertTrue(Gate::forUser($admin)->allows('update', $member));
        $this->assertSame(['User'], $member->roles->pluck('name')->all());
        $this->assertSame($otherOrganization->id, app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    public static function userMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, true],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, true],
            ['Organization Owner', 'delete', false, false],
            ['Organization Owner', 'deleteAny', true, true],
            ['Organization Owner', 'restore', true, true],
            ['Organization Owner', 'restore', false, false],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, true],
            ['Organization Admin', 'update', true, true],
            ['Organization Admin', 'update', false, false],
            ['Organization Admin', 'delete', true, false],
            ['Organization Admin', 'deleteAny', true, false],
            ['Organization Admin', 'restore', true, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['User', 'viewAny', true, true],
            ['User', 'view', true, true],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:users.delete', 'delete', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    public static function organizationMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, false],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, false],
            ['Organization Owner', 'deleteAny', true, false],
            ['Organization Owner', 'restore', true, false],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, false],
            ['Organization Admin', 'update', true, false],
            ['Organization Admin', 'delete', true, false],
            ['Organization Admin', 'deleteAny', true, false],
            ['Organization Admin', 'restore', true, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['User', 'viewAny', true, true],
            ['User', 'view', true, true],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:organizations.update', 'update', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    public static function organizationBrandingMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, true],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, true],
            ['Organization Owner', 'delete', false, false],
            ['Organization Owner', 'deleteAny', true, true],
            ['Organization Owner', 'restore', true, true],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, false],
            ['Organization Admin', 'update', true, false],
            ['Organization Admin', 'delete', true, false],
            ['Organization Admin', 'deleteAny', true, false],
            ['Organization Admin', 'restore', true, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['User', 'viewAny', true, true],
            ['User', 'view', true, true],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:organizations.update', 'update', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    public static function invitationMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, true],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, true],
            ['Organization Owner', 'delete', false, false],
            ['Organization Owner', 'deleteAny', true, true],
            ['Organization Owner', 'restore', true, true],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, true],
            ['Organization Admin', 'update', true, true],
            ['Organization Admin', 'update', false, false],
            ['Organization Admin', 'delete', true, true],
            ['Organization Admin', 'delete', false, false],
            ['Organization Admin', 'deleteAny', true, true],
            ['Organization Admin', 'restore', true, true],
            ['Organization Admin', 'forceDelete', true, false],
            ['User', 'viewAny', true, false],
            ['User', 'view', true, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:users.create', 'delete', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    private function actor(string $role): User
    {
        if ($role === 'no organization') {
            $user = $this->createUser([], 'Organization Owner', 'web');
            $user->update(['organization_id' => null]);

            return $user;
        }

        if (str_starts_with($role, 'custom:')) {
            $user = $this->createUser([], 'User', 'web');
            CustomRole::factory()->forOrganization($user->organization)
                ->create(['permissions' => [substr($role, strlen('custom:'))]])
                ->assignToUser($user);

            return $user;
        }

        return $this->createUser([], $role, 'web');
    }

    /**
     * @param  class-string<Model>  $modelClass
     * @param  callable(int): Model  $makeRecord
     */
    private function assertAbility(bool $expected, User $actor, string $ability, string $modelClass, callable $makeRecord, bool $sameOrg): void
    {
        if (in_array($ability, self::RECORDLESS_ABILITIES, true)) {
            $this->assertSame($expected, Gate::forUser($actor)->allows($ability, $modelClass));

            return;
        }

        $organizationId = $sameOrg ? $actor->organization_id : Organization::factory()->create()->id;
        $record = $makeRecord($organizationId);

        $this->assertSame($expected, Gate::forUser($actor)->allows($ability, $record));
    }
}
