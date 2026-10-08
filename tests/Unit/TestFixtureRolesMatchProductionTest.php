<?php

namespace Tests\Unit;

use Database\Seeders\RolePermissionSeeder;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class TestFixtureRolesMatchProductionTest extends TestCase
{
    #[Test]
    public function it_gives_organization_roles_the_production_permissions_on_both_guards(): void
    {
        foreach (['web', 'api'] as $guard) {
            $user = $this->createUser([], 'Organization Owner', $guard);
            $organization = $user->organization;

            foreach ($organization->getDefaultRoles() as $roleName => $expected) {
                $this->createUser(['organization_id' => $organization->id], $roleName, $guard);

                $actual = Role::where('name', $roleName)
                    ->where('guard_name', $guard)
                    ->where('organization_id', $organization->id)
                    ->firstOrFail()
                    ->permissions->pluck('name')->all();

                $this->assertEqualsCanonicalizing($expected, $actual, "{$roleName} on {$guard}");
            }
        }
    }

    #[Test]
    public function it_gives_global_roles_the_seeder_permissions(): void
    {
        $constants = (new ReflectionClass(RolePermissionSeeder::class))->getConstants();

        $this->createUser([], 'Super Admin', 'web');
        $this->createUser([], 'Super Admin', 'api');

        $this->assertEqualsCanonicalizing(
            $constants['GLOBAL_PERMISSIONS'],
            $this->globalRolePermissions('Super Admin', 'web')
        );
        $this->assertEqualsCanonicalizing(
            $constants['GLOBAL_PERMISSIONS'],
            $this->globalRolePermissions('Super Admin', 'api')
        );
    }

    #[Test]
    public function it_seeds_the_system_administrator_role_from_the_seeder(): void
    {
        $constants = (new ReflectionClass(RolePermissionSeeder::class))->getConstants();

        $this->createUser([], 'Super Admin', 'web');

        $this->assertEqualsCanonicalizing(
            $constants['SYSTEM_ADMINISTRATOR_PERMISSIONS'],
            $this->globalRolePermissions('System Administrator', 'web')
        );
    }

    private function globalRolePermissions(string $name, string $guard): array
    {
        return Role::where('name', $name)
            ->where('guard_name', $guard)
            ->whereNull('organization_id')
            ->firstOrFail()
            ->permissions->pluck('name')->all();
    }
}
