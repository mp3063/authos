<?php

namespace Tests\Unit\Policies;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class RoleAndPermissionPolicyMatrixTest extends TestCase
{
    private const RECORDLESS_ABILITIES = ['viewAny', 'create', 'deleteAny'];

    #[Test]
    #[DataProvider('roleMatrix')]
    public function it_applies_the_matrix_to_roles(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, Role::class,
            fn (int $organizationId) => Role::create(['name' => 'Scoped '.uniqid(), 'guard_name' => 'web', 'organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('permissionMatrix')]
    public function it_applies_the_matrix_to_permissions(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, Permission::class,
            fn (int $organizationId) => Permission::create(['name' => 'scoped.'.uniqid(), 'guard_name' => 'web', 'organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('customRoleMatrix')]
    public function it_applies_the_matrix_to_custom_roles(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, CustomRole::class,
            fn (int $organizationId) => CustomRole::factory()->forOrganization(Organization::findOrFail($organizationId))->create(), $sameOrg);
    }

    #[Test]
    public function it_lets_anyone_holding_permissions_read_view_a_global_permission(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $member = $this->createUser([], 'User', 'web');
        $permission = Permission::create(['name' => 'global.'.uniqid(), 'guard_name' => 'web', 'organization_id' => null]);

        $this->assertTrue(Gate::forUser($admin)->allows('view', $permission));
        $this->assertFalse(Gate::forUser($member)->allows('view', $permission));
    }

    #[Test]
    public function it_lets_anyone_holding_roles_read_view_a_global_role(): void
    {
        $admin = $this->createUser([], 'Organization Admin', 'web');
        $member = $this->createUser([], 'User', 'web');
        $globalRole = Role::create(['name' => 'Global '.uniqid(), 'guard_name' => 'web', 'organization_id' => null]);

        $this->assertTrue(Gate::forUser($admin)->allows('view', $globalRole));
        $this->assertFalse(Gate::forUser($member)->allows('view', $globalRole));
    }

    public static function roleMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, false],
            ['Organization Owner', 'update', true, false],
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
            ['User', 'viewAny', true, false],
            ['User', 'view', true, false],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:roles.read', 'view', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    public static function permissionMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'create', true, false],
            ['Organization Owner', 'update', true, false],
            ['Organization Owner', 'delete', true, false],
            ['Organization Owner', 'deleteAny', true, false],
            ['Organization Owner', 'restore', true, false],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'create', true, false],
            ['Organization Admin', 'update', true, false],
            ['Organization Admin', 'delete', true, false],
            ['Organization Admin', 'deleteAny', true, false],
            ['Organization Admin', 'restore', true, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['User', 'viewAny', true, false],
            ['User', 'view', false, false],
            ['User', 'view', true, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:permissions.read', 'viewAny', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    public static function customRoleMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, false],
            ['Organization Owner', 'update', true, false],
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
            ['User', 'viewAny', true, false],
            ['User', 'view', true, false],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:roles.read', 'view', true, true],
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
