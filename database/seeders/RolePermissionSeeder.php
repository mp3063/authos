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
            'view organizations',
            'create organizations',
            'edit organizations',
            'delete organizations',
            
            // Application permissions
            'view applications',
            'create applications',
            'edit applications',
            'delete applications',
            'regenerate application secrets',
            
            // User permissions
            'view users',
            'create users',
            'edit users',
            'delete users',
            'impersonate users',
            
            // Authentication logs
            'view authentication logs',
            'export authentication logs',
            
            // System permissions
            'view system settings',
            'edit system settings',
            'view analytics',
            'manage oauth clients',
            
            // Admin permissions
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
            'access admin panel',
            'view organizations',
            'edit organizations',
            'view applications',
            'create applications',
            'edit applications',
            'delete applications',
            'regenerate application secrets',
            'view users',
            'create users',
            'edit users',
            'view authentication logs',
            'export authentication logs',
            'view analytics',
        ]);

        $developerRole = Role::create(['name' => 'Developer']);
        $developerRole->givePermissionTo([
            'access admin panel',
            'view applications',
            'create applications',
            'edit applications',
            'regenerate application secrets',
            'view users',
            'view authentication logs',
            'manage oauth clients',
        ]);

        $viewerRole = Role::create(['name' => 'Viewer']);
        $viewerRole->givePermissionTo([
            'access admin panel',
            'view organizations',
            'view applications',
            'view users',
            'view authentication logs',
        ]);
    }
}
