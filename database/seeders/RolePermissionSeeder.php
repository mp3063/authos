<?php

namespace Database\Seeders;

use App\Models\Organization;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

class RolePermissionSeeder extends Seeder
{
    private const GLOBAL_PERMISSIONS = [
        // System administration
        'system.settings.read',
        'system.settings.update',
        'system.analytics.read',
        'oauth.manage',
        'admin.access',

        // Global organization management (for super admins)
        'organizations.create',
        'organizations.delete',
        'organizations.manage_global',

        // Global user management (for super admins)
        'users.create',
        'users.read',
        'users.update',
        'users.delete',
        'applications.create',
        'applications.read',
        'applications.update',
        'applications.delete',
        'roles.create',
        'roles.read',
        'roles.update',
        'roles.delete',
        'permissions.create',
        'permissions.read',
        'permissions.update',
        'permissions.delete',
        'auth_logs.read',
        'auth_logs.export',

        // Legacy global permissions
        'access admin panel',
        'create organizations',
        'delete organizations',
        'view system settings',
        'edit system settings',
        'view analytics',
        'manage oauth clients',
    ];

    private const SYSTEM_ADMINISTRATOR_PERMISSIONS = [
        'system.settings.read',
        'system.analytics.read',
        'admin.access',
        'access admin panel',
        'view system settings',
        'view analytics',
    ];

    public function run(): void
    {
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        $this->createGlobalPermissions();
        $this->createGlobalRoles();

        foreach (Organization::all() as $organization) {
            $organization->setupDefaultRoles();
        }
    }

    private function createGlobalPermissions(): void
    {
        foreach (self::GLOBAL_PERMISSIONS as $permission) {
            Permission::firstOrCreate(['name' => $permission, 'guard_name' => 'web', 'organization_id' => null]);
            Permission::firstOrCreate(['name' => $permission, 'guard_name' => 'api', 'organization_id' => null]);
        }
    }

    private function createGlobalRoles(): void
    {
        $this->globalRole('Super Admin', 'web')->givePermissionTo(self::GLOBAL_PERMISSIONS);
        $this->globalRole('Super Admin', 'api')->givePermissionTo(
            Permission::where('guard_name', 'api')->where('organization_id', null)->pluck('name')
        );

        $this->globalRole('System Administrator', 'web')->givePermissionTo(self::SYSTEM_ADMINISTRATOR_PERMISSIONS);
        $this->globalRole('System Administrator', 'api')->givePermissionTo(self::SYSTEM_ADMINISTRATOR_PERMISSIONS);
    }

    private function globalRole(string $name, string $guard): Role
    {
        return Role::firstOrCreate(['name' => $name, 'guard_name' => $guard, 'organization_id' => null]);
    }
}
