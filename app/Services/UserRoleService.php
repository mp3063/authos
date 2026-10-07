<?php

namespace App\Services;

use App\Models\Role;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Collection;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Exists;
use Spatie\Permission\Models\Role as SpatieRole;

class UserRoleService
{
    /**
     * Validation rule: the role exists and the caller may grant it to a member of the organization.
     */
    public function assignableRoleRule(User $caller, ?int $organizationId, string $column): Exists
    {
        return Rule::exists('roles', $column)
            ->where(fn (QueryBuilder $query) => $this->scopeToAssignableRoles($query, $caller, $organizationId));
    }

    /**
     * @param  list<string>  $names
     * @return EloquentCollection<int, Role>
     */
    public function assignableApiRolesByName(User $caller, ?int $organizationId, array $names): EloquentCollection
    {
        return Role::query()
            ->where('guard_name', 'api')
            ->whereIn('name', $names)
            ->where(fn (Builder $query) => $this->scopeToAssignableRoles($query, $caller, $organizationId))
            ->get();
    }

    /**
     * Why the caller may not grant or revoke these roles for the target (null for a user being created), if not allowed.
     *
     * @param  EloquentCollection<int, Role>  $roles
     */
    public function roleChangeDenial(User $caller, ?User $target, EloquentCollection $roles): ?string
    {
        if ($caller->isSuperAdmin()) {
            return null;
        }

        if ($target !== null && $caller->is($target)) {
            return 'You cannot change your own roles.';
        }

        $callerPermissions = $caller->getAllPermissions()->pluck('name');
        $exceedsCaller = $roles->load('permissions')
            ->flatMap(fn (Role $role) => $role->permissions->pluck('name'))
            ->diff($callerPermissions)
            ->isNotEmpty();

        return $exceedsCaller ? 'You cannot grant or revoke a role with permissions you do not have.' : null;
    }

    private function scopeToAssignableRoles(Builder|QueryBuilder $query, User $caller, ?int $organizationId): void
    {
        $query->where(fn ($organizationRoles) => $organizationRoles
            ->whereNotNull('organization_id')
            ->where('organization_id', $organizationId));

        if ($caller->isSuperAdmin()) {
            $query->orWhereNull('organization_id');
        }
    }

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
