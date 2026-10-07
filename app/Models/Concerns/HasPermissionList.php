<?php

namespace App\Models\Concerns;

trait HasPermissionList
{
    /**
     * Check if the role has a specific permission
     */
    public function hasPermission(string $permission): bool
    {
        $permissions = $this->permissions ?? [];

        return in_array($permission, $permissions);
    }

    /**
     * Add a permission to this role
     */
    public function grantPermission(string $permission): void
    {
        $permissions = $this->permissions ?? [];
        if (! in_array($permission, $permissions)) {
            $permissions[] = $permission;
            $this->update(['permissions' => $permissions]);
        }
    }

    /**
     * Remove a permission from this role
     */
    public function revokePermission(string $permission): void
    {
        $permissions = $this->permissions ?? [];
        $filteredPermissions = array_filter($permissions, fn ($existingPermission) => $existingPermission !== $permission);
        $this->update(['permissions' => array_values($filteredPermissions)]);
    }

    /**
     * Sync permissions for this role
     */
    public function syncPermissions(array $permissions): void
    {
        $this->update(['permissions' => $permissions]);
    }

    /**
     * Add a permission to this role (alias for grantPermission)
     */
    public function addPermission(string $permission): void
    {
        $this->grantPermission($permission);
    }

    /**
     * Remove a permission from this role (alias for revokePermission)
     */
    public function removePermission(string $permission): void
    {
        $this->revokePermission($permission);
    }

    /**
     * Add multiple permissions to this role
     */
    public function addPermissions(array $permissions): void
    {
        $currentPermissions = $this->permissions ?? [];
        $newPermissions = array_unique(array_merge($currentPermissions, $permissions));
        $this->update(['permissions' => $newPermissions]);
    }

    /**
     * Remove multiple permissions from this role
     */
    public function removePermissions(array $permissions): void
    {
        $currentPermissions = $this->permissions ?? [];
        $filteredPermissions = array_filter($currentPermissions, fn ($existingPermission) => ! in_array($existingPermission, $permissions));
        $this->update(['permissions' => array_values($filteredPermissions)]);
    }

    /**
     * Get the count of permissions for this role
     */
    public function getPermissionCount(): int
    {
        return count($this->permissions ?? []);
    }

    /**
     * Check if this is an admin role (has admin-level permissions)
     */
    public function isAdminRole(): bool
    {
        $adminPermissions = ['users.delete', 'organization.manage_settings', 'roles.create', 'roles.delete'];
        $currentPermissions = $this->permissions ?? [];

        return ! empty(array_intersect($adminPermissions, $currentPermissions));
    }

    /**
     * Check if the role can manage users
     */
    public function canManageUsers(): bool
    {
        $userManagementPermissions = ['users.create', 'users.update', 'users.delete', 'users.manage_roles'];
        $currentPermissions = $this->permissions ?? [];

        return ! empty(array_intersect($userManagementPermissions, $currentPermissions));
    }

    /**
     * Check if the role can manage applications
     */
    public function canManageApplications(): bool
    {
        $appManagementPermissions = ['applications.create', 'applications.update', 'applications.delete', 'applications.manage_users'];
        $currentPermissions = $this->permissions ?? [];

        return ! empty(array_intersect($appManagementPermissions, $currentPermissions));
    }

    /**
     * Get permissions grouped by their prefix (category)
     */
    public function getGroupedPermissions(): array
    {
        $permissions = $this->permissions ?? [];
        $grouped = [];

        foreach ($permissions as $permission) {
            $parts = explode('.', $permission);
            $category = $parts[0] ?? 'other';

            if (! isset($grouped[$category])) {
                $grouped[$category] = [];
            }

            $grouped[$category][] = $permission;
        }

        return $grouped;
    }
}
