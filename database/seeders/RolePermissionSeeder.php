<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class RolePermissionSeeder extends Seeder
{
    public function run(): void
    {
        // Reset cached roles and permissions
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        // Create permissions
        $permissions = [
            // Organization permissions
            'organizations.read',
            'organizations.create',
            'organizations.update', 
            'organizations.delete',
            'organizations.manage_users',
            
            // Application permissions
            'applications.read',
            'applications.create',
            'applications.update',
            'applications.delete',
            'applications.regenerate_credentials',
            
            // User permissions
            'users.read',
            'users.create',
            'users.update',
            'users.delete',
            'users.impersonate',
            
            // Role and permission management
            'roles.assign',
            'roles.read',
            'roles.create',
            'roles.update',
            'roles.delete',
            'permissions.read',
            'permissions.create',
            'permissions.update', 
            'permissions.delete',
            
            // Authentication logs
            'auth_logs.read',
            'auth_logs.export',
            
            // System permissions
            'system.settings.read',
            'system.settings.update',
            'system.analytics.read',
            'oauth.manage',
            
            // Admin panel access
            'admin.access',
            
            // Legacy permissions for backwards compatibility
            'view organizations',
            'create organizations',
            'edit organizations',
            'delete organizations',
            'view applications',
            'create applications', 
            'edit applications',
            'delete applications',
            'regenerate application secrets',
            'view users',
            'create users',
            'edit users',
            'delete users',
            'impersonate users',
            'view authentication logs',
            'export authentication logs',
            'view system settings',
            'edit system settings',
            'view analytics',
            'manage oauth clients',
            'access admin panel',
            'manage roles',
            'manage permissions',
        ];

        foreach ($permissions as $permission) {
            Permission::create(['name' => $permission]);
        }

        // Create roles and assign permissions
        $superAdminRole = Role::create(['name' => 'Super Admin']);
        $superAdminRole->givePermissionTo(Permission::all());

        $orgAdminRole = Role::create(['name' => 'Organization Admin']);
        $orgAdminRole->givePermissionTo([
            // Admin panel access
            'admin.access',
            'access admin panel',
            
            // Organization management
            'organizations.read',
            'organizations.update',
            'organizations.manage_users',
            'view organizations',
            'edit organizations',
            
            // Application management
            'applications.read',
            'applications.create',
            'applications.update',
            'applications.delete',
            'applications.regenerate_credentials',
            'view applications',
            'create applications',
            'edit applications',
            'delete applications',
            'regenerate application secrets',
            
            // User management
            'users.read',
            'users.create',
            'users.update',
            'view users',
            'create users',
            'edit users',
            
            // Analytics and logs
            'auth_logs.read',
            'auth_logs.export',
            'system.analytics.read',
            'view authentication logs',
            'export authentication logs',
            'view analytics',
        ]);

        $developerRole = Role::create(['name' => 'Developer']);
        $developerRole->givePermissionTo([
            // Admin panel access
            'admin.access',
            'access admin panel',
            
            // Application management
            'applications.read',
            'applications.create',
            'applications.update',
            'applications.regenerate_credentials',
            'view applications',
            'create applications',
            'edit applications',
            'regenerate application secrets',
            
            // User read access
            'users.read',
            'view users',
            
            // OAuth and logs
            'oauth.manage',
            'auth_logs.read',
            'view authentication logs',
            'manage oauth clients',
        ]);

        $viewerRole = Role::create(['name' => 'Viewer']);
        $viewerRole->givePermissionTo([
            // Admin panel access
            'admin.access',
            'access admin panel',
            
            // Read-only access
            'organizations.read',
            'applications.read',
            'users.read',
            'auth_logs.read',
            'view organizations',
            'view applications',
            'view users',
            'view authentication logs',
        ]);
    }
}
