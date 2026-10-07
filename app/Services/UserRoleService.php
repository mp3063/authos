<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Collection;
use Spatie\Permission\Models\Role as SpatieRole;

class UserRoleService
{
    /**
     * Assign role to user
     */
    public function assignRole(User $user, string $roleId): bool
    {
        $role = SpatieRole::findOrFail($roleId);

        if ($user->hasRole($role)) {
            return false;
        }

        // Guard is handled by User model's getDefaultGuardName() method
        $user->assignRole($role);

        return true;
    }

    /**
     * Remove role from user
     */
    public function removeRole(User $user, string $roleId): bool
    {
        $role = SpatieRole::findOrFail($roleId);

        if (! $user->hasRole($role)) {
            return false;
        }

        $user->removeRole($role);

        return true;
    }

    /**
     * Format user roles response
     */
    public function formatUserRolesResponse(Collection $roles): array
    {
        return $roles->map(function ($role) {
            return [
                'id' => $role->id,
                'name' => $role->name,
                'display_name' => $role->display_name ?? ucfirst($role->name),
                'permissions' => $role->permissions->pluck('name'),
            ];
        })->toArray();
    }
}
