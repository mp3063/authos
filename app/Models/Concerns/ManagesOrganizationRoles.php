<?php

namespace App\Models\Concerns;

use App\Models\CustomRole;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

trait ManagesOrganizationRoles
{
    public function roles(): HasMany
    {
        return $this->hasMany(Role::class);
    }

    public function permissions(): HasMany
    {
        return $this->hasMany(Permission::class);
    }

    public function customRoles(): HasMany
    {
        return $this->hasMany(CustomRole::class);
    }

    /**
     * Create a new role for this organization
     */
    public function createRole(string $name, array $permissions = [], string $guard = 'web'): Role
    {
        $role = Role::firstOrCreate([
            'name' => $name,
            'guard_name' => $guard,
            'organization_id' => $this->id,
        ]);

        if (! empty($permissions)) {
            $role->givePermissionTo($permissions);
        }

        return $role;
    }

    /**
     * Create a new permission for this organization
     */
    public function createPermission(string $name, string $guardName = 'web'): Permission
    {
        return Permission::create([
            'name' => $name,
            'guard_name' => $guardName,
            'organization_id' => $this->id,
        ]);
    }

    /**
     * Get default roles that should be created for this organization
     */
    public function getDefaultRoles(): array
    {
        return [
            'Organization Owner' => [
                'users.create', 'users.read', 'users.update', 'users.delete',
                'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                'applications.regenerate_credentials',
                'organizations.read', 'organizations.update',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete',
                'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                'auth_logs.read', 'auth_logs.export',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
            ],
            'Organization Admin' => [
                'users.create', 'users.read', 'users.update',
                'applications.create', 'applications.read', 'applications.update',
                'organizations.read',
                'roles.read', 'roles.assign',
                'permissions.read',
                'auth_logs.read',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
            ],
            'Organization Member' => [
                'users.read',
                'applications.read',
                'organizations.read',
            ],
            'Application Manager' => [
                'applications.create', 'applications.read', 'applications.update',
                'applications.regenerate_credentials',
                'users.read',
            ],
            'User Manager' => [
                'users.create', 'users.read', 'users.update',
                'roles.read', 'roles.assign',
                'applications.read',
            ],
            'Auditor' => [
                'users.read',
                'applications.read',
                'organizations.read',
                'auth_logs.read', 'auth_logs.export',
            ],
            'User' => [
                'users.read',
                'applications.read',
                'organizations.read',
            ],
        ];
    }

    /**
     * Setup default roles and permissions for this organization
     */
    public function setupDefaultRoles(): void
    {
        $defaultRoles = $this->getDefaultRoles();

        // First, ensure all required permissions exist for this organization
        $allRequiredPermissions = collect($defaultRoles)->flatten()->unique();

        foreach ($allRequiredPermissions as $permissionName) {
            // Create permission for web guard
            Permission::firstOrCreate([
                'name' => $permissionName,
                'guard_name' => 'web',
                'organization_id' => $this->id,
            ]);

            // Also create permission for api guard for API authentication
            Permission::firstOrCreate([
                'name' => $permissionName,
                'guard_name' => 'api',
                'organization_id' => $this->id,
            ]);
        }

        // Then create roles and assign permissions for both web and api guards
        foreach ($defaultRoles as $roleName => $permissions) {
            // Create role for web guard
            $existingWebRole = Role::where('name', $roleName)
                ->where('guard_name', 'web')
                ->where('organization_id', $this->id)
                ->first();

            if (! $existingWebRole) {
                $this->createRole($roleName, $permissions, 'web');
            }

            // Create role for api guard
            $existingApiRole = Role::where('name', $roleName)
                ->where('guard_name', 'api')
                ->where('organization_id', $this->id)
                ->first();

            if (! $existingApiRole) {
                $this->createRole($roleName, $permissions, 'api');
            }
        }
    }

    /**
     * Get all permissions available to this organization (org-specific + global)
     */
    public function getAvailablePermissions(): Collection
    {
        return Permission::where(function ($query) {
            $query->where('organization_id', $this->id)
                ->orWhereNull('organization_id');
        })->get();
    }

    /**
     * Get all roles available to this organization (org-specific + global)
     */
    public function getAvailableRoles(): Collection
    {
        return Role::where(function ($query) {
            $query->where('organization_id', $this->id)
                ->orWhereNull('organization_id');
        })->get();
    }
}
