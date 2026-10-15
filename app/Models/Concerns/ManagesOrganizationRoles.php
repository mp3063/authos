<?php

namespace App\Models\Concerns;

use App\Models\CustomRole;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

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
                'organizations.read', 'organizations.update',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                'auth_logs.read', 'auth_logs.export',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
                'admin.access',
            ],
            'Organization Admin' => [
                'users.create', 'users.read', 'users.update',
                'applications.create', 'applications.read', 'applications.update',
                'organizations.read',
                'roles.read', 'roles.assign',
                'permissions.read',
                'auth_logs.read',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
                'admin.access',
            ],
            'Organization Member' => [
                'users.read',
                'applications.read',
                'organizations.read',
            ],
            'Application Manager' => [
                'applications.create', 'applications.read', 'applications.update',
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
        $permissionNames = collect($defaultRoles)->flatten()->unique()->values();
        $registrar = app(PermissionRegistrar::class);

        $now = now();

        foreach (['web', 'api'] as $guard) {
            $existing = Permission::where('guard_name', $guard)
                ->where('organization_id', $this->id)
                ->whereIn('name', $permissionNames)
                ->pluck('name');

            Permission::insert($permissionNames->diff($existing)->map(fn (string $name): array => [
                'name' => $name,
                'guard_name' => $guard,
                'organization_id' => $this->id,
                'created_at' => $now,
                'updated_at' => $now,
            ])->values()->all());
        }

        foreach (['web', 'api'] as $guard) {
            $existingRoles = Role::where('guard_name', $guard)
                ->where('organization_id', $this->id)
                ->whereIn('name', array_keys($defaultRoles))
                ->pluck('name');
            $missingRoles = collect($defaultRoles)->except($existingRoles->all());

            if ($missingRoles->isEmpty()) {
                continue;
            }

            Role::insert($missingRoles->keys()->map(fn (string $name): array => [
                'name' => $name,
                'guard_name' => $guard,
                'organization_id' => $this->id,
                'created_at' => $now,
                'updated_at' => $now,
            ])->all());

            $roleIds = Role::where('guard_name', $guard)
                ->where('organization_id', $this->id)
                ->whereIn('name', $missingRoles->keys())
                ->pluck('id', 'name');
            $permissionIds = Permission::where('guard_name', $guard)
                ->where('organization_id', $this->id)
                ->whereIn('name', $permissionNames)
                ->pluck('id', 'name');

            DB::table(config('permission.table_names.role_has_permissions'))->insert(
                $missingRoles->flatMap(fn (array $names, string $roleName) => collect($names)
                    ->map(fn (string $name): array => ['permission_id' => $permissionIds[$name], 'role_id' => $roleIds[$roleName]]))
                    ->values()
                    ->all()
            );
        }

        $registrar->forgetCachedPermissions();
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
