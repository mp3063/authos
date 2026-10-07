<?php

namespace App\Models\Concerns;

use App\Models\CustomRole;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Spatie\Permission\Exceptions\RoleDoesNotExist;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

trait InteractsWithOrganizationRoles
{
    public function customRoles(): BelongsToMany
    {
        return $this->belongsToMany(CustomRole::class, 'user_custom_roles')
            ->withPivot(['granted_at', 'granted_by'])
            ->withTimestamps();
    }

    /**
     * Check if user has a permission via CustomRole
     */
    public function hasCustomPermission(string $permission): bool
    {
        return $this->customRoles()
            ->where('is_active', true)
            ->get()
            ->contains(fn (CustomRole $role) => $role->hasPermission($permission));
    }

    /**
     * Set the organization context for permission/role operations
     */
    public function setPermissionsTeamId($organizationId = null): void
    {
        $this->permissionsTeamId = $organizationId ?? $this->organization_id;
    }

    /**
     * Get roles for a specific organization
     */
    public function getOrganizationRoles($organizationId = null)
    {
        $orgId = $organizationId ?? $this->organization_id;

        return $this->roles()
            ->where(function ($query) use ($orgId) {
                $query->where('roles.organization_id', $orgId)
                    ->orWhereNull('roles.organization_id'); // Include global roles
            })
            ->get();
    }

    /**
     * Get permissions for a specific organization
     */
    public function getOrganizationPermissions($organizationId = null)
    {
        $orgId = $organizationId ?? $this->organization_id;

        // Get permissions from roles
        $rolePermissions = $this->getOrganizationRoles($orgId)
            ->flatMap(fn ($role) => $role->permissions);

        // Get direct permissions
        $directPermissions = $this->permissions()
            ->where(function ($query) use ($orgId) {
                $query->where('permissions.organization_id', $orgId)
                    ->orWhereNull('permissions.organization_id'); // Include global permissions
            })
            ->get();

        return $rolePermissions->merge($directPermissions)->unique('id');
    }

    /**
     * Check if user has a role within their organization
     */
    public function hasOrganizationRole($role, $organizationId = null): bool
    {
        $orgId = $organizationId ?? $this->organization_id;
        $this->setPermissionsTeamId($orgId);

        return $this->hasRole($role);
    }

    /**
     * Check if user has a permission within their organization
     */
    public function hasOrganizationPermission($permission, $organizationId = null): bool
    {
        $orgId = $organizationId ?? $this->organization_id;
        $this->setPermissionsTeamId($orgId);

        return $this->hasPermissionTo($permission);
    }

    /**
     * Assign role to user within organization context
     */
    public function assignOrganizationRole($role, $organizationId = null): void
    {
        $orgId = $organizationId ?? $this->organization_id;

        // Find the role within the organization context
        $roleModel = Role::where('name', $role)
            ->where('organization_id', $orgId)
            ->first();

        if (! $roleModel) {
            throw new RoleDoesNotExist("Role '$role' does not exist for organization $orgId");
        }

        // Attach the role with organization context
        $this->roles()->attach($roleModel->id, ['organization_id' => $orgId]);
    }

    /**
     * Assign a global role to user (bypasses organization context)
     */
    public function assignGlobalRole($role): void
    {
        // For global roles, we directly assign without organization context
        $this->roles()->attach(
            Role::where('name', $role)
                ->whereNull('organization_id')
                ->first()
        );
    }

    /**
     * Remove role from user within organization context
     */
    public function removeOrganizationRole($role, $organizationId = null): void
    {
        $orgId = $organizationId ?? $this->organization_id;
        $this->setPermissionsTeamId($orgId);

        $this->removeRole($role);
    }

    /**
     * Check if user is owner of their organization
     */
    public function isOrganizationOwner(): bool
    {
        return $this->hasOrganizationRole('Organization Owner');
    }

    /**
     * Check if user is admin of their organization
     */
    public function isOrganizationAdmin(): bool
    {
        return $this->hasOrganizationRole('Organization Admin') ||
               $this->hasOrganizationRole('organization admin') ||
               $this->isOrganizationOwner();
    }

    /**
     * Check if user has global system roles
     */
    public function hasGlobalRole($role): bool
    {
        // Temporarily clear team context to check global roles
        $registrar = app(PermissionRegistrar::class);
        $registrarTeamId = $registrar->getPermissionsTeamId();

        // Clear team context
        $this->setPermissionsTeamId(null);
        $registrar->setPermissionsTeamId(null);

        try {
            $hasRole = $this->roles()->where('roles.name', $role)->whereNull('roles.organization_id')->exists();
        } finally {
            // Restore original team context
            $this->setPermissionsTeamId($registrarTeamId);
            $registrar->setPermissionsTeamId($registrarTeamId);
        }

        return $hasRole;
    }

    /**
     * Check if user is a super admin (global role)
     */
    public function isSuperAdmin(): bool
    {
        return $this->hasGlobalRole('Super Admin');
    }
}
