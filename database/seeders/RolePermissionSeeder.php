<?php

namespace Database\Seeders;

use App\Models\Organization;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

class RolePermissionSeeder extends Seeder
{
    public function run(): void
    {
        // Reset cached roles and permissions
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        // Create global system permissions (for system-wide operations)
        $globalPermissions = [
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

        foreach ($globalPermissions as $permission) {
            // Create permissions for both web and api guards
            Permission::firstOrCreate(
              [
                'name' => $permission,
                'guard_name' => 'web',
                'organization_id' => null,
              ],
              [
                'name' => $permission,
                'guard_name' => 'web',
                'organization_id' => null, // Global permission
              ]
            );

            Permission::firstOrCreate(
              [
                'name' => $permission,
                'guard_name' => 'api',
                'organization_id' => null,
              ],
              [
                'name' => $permission,
                'guard_name' => 'api',
                'organization_id' => null, // Global permission
              ]
            );
        }

        // Create global system roles for both web and api guards
        $superAdminRole = Role::firstOrCreate(
          [
            'name' => 'Super Admin',
            'guard_name' => 'web',
            'organization_id' => null,
          ],
          [
            'name' => 'Super Admin',
            'guard_name' => 'web',
            'organization_id' => null, // Global role
          ]
        );
        $superAdminRole->givePermissionTo($globalPermissions);

        $superAdminApiRole = Role::firstOrCreate(
          [
            'name' => 'Super Admin',
            'guard_name' => 'api',
            'organization_id' => null,
          ],
          [
            'name' => 'Super Admin',
            'guard_name' => 'api',
            'organization_id' => null, // Global role
          ]
        );
        $superAdminApiRole->givePermissionTo(Permission::where('guard_name', 'api')->where('organization_id', null)->pluck('name'));

        $systemAdminRole = Role::firstOrCreate(
          [
            'name' => 'System Administrator',
            'guard_name' => 'web',
            'organization_id' => null,
          ],
          [
            'name' => 'System Administrator',
            'guard_name' => 'web',
            'organization_id' => null, // Global role
          ]
        );
        $systemAdminRole->givePermissionTo([
          'system.settings.read',
          'system.analytics.read',
          'admin.access',
          'access admin panel',
          'view system settings',
          'view analytics',
        ]);

        $systemAdminApiRole = Role::firstOrCreate(
          [
            'name' => 'System Administrator',
            'guard_name' => 'api',
            'organization_id' => null,
          ],
          [
            'name' => 'System Administrator',
            'guard_name' => 'api',
            'organization_id' => null, // Global role
          ]
        );
        $systemAdminApiRole->givePermissionTo([
          'system.settings.read',
          'system.analytics.read',
          'admin.access',
          'access admin panel',
          'view system settings',
          'view analytics',
        ]);

        // Create organization-scoped roles and permissions for each organization
        $organizations = Organization::all();

        foreach ($organizations as $organization) {
            $this->createOrganizationRolesAndPermissions($organization);

            // Setup default roles for the organization (this calls setupDefaultRoles())
            $organization->setupDefaultRoles();
        }
    }

    /**
     * Create roles and permissions for a specific organization
     */
    private function createOrganizationRolesAndPermissions(Organization $organization): void
    {
        // Note: All organization-specific roles and permissions are now created 
        // in setupDefaultRoles() method to avoid conflicts

        // This method can be used for any additional setup if needed in the future
    }
}
