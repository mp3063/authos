<?php

namespace App\Services;

use App\Models\Role;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Exists;
use Illuminate\Validation\ValidationException;
use Spatie\Permission\Models\Role as SpatieRole;
use Spatie\Permission\PermissionRegistrar;

class UserRoleService
{
    /**
     * Roles the editor may grant to or revoke from a member of the organization.
     *
     * @return EloquentCollection<int, Role>
     */
    public function manageableRoles(User $editor, ?int $organizationId): EloquentCollection
    {
        return Role::query()
            ->where(fn (Builder $query) => $this->scopeToAssignableRoles($query, $editor, $organizationId))
            ->get()
            ->filter(fn (Role $role) => $this->roleChangeDenial($editor, null, new EloquentCollection([$role])) === null)
            ->values();
    }

    /**
     * @return Collection<int, int>
     */
    public function assignedRoleIds(User $user): Collection
    {
        return DB::table('model_has_roles')
            ->where('model_type', $user->getMorphClass())
            ->where('model_id', $user->id)
            ->pluck('role_id')
            ->map(fn ($id) => (int) $id);
    }

    /**
     * Why the editor may not replace the target's roles with these (target null for a user being created), if not allowed.
     *
     * @param  Collection<int, int>  $roleIds
     */
    public function roleSyncDenial(User $editor, ?User $target, ?int $organizationId, Collection $roleIds): ?string
    {
        if ($editor->isSuperAdmin()) {
            return null;
        }

        $current = $target ? $this->assignedRoleIds($target) : collect();
        $changed = $roleIds->diff($current)->merge($current->diff($roleIds));

        if ($changed->isEmpty()) {
            return null;
        }

        if ($target !== null && $editor->is($target)) {
            return 'You cannot change your own roles.';
        }

        return $changed->diff($this->manageableRoles($editor, $organizationId)->modelKeys())->isEmpty()
            ? null
            : 'You cannot grant or revoke these roles.';
    }

    /**
     * Replace the target's roles, tying each organization role to its organization.
     *
     * @param  Collection<int, int>  $roleIds
     *
     * @throws ValidationException
     */
    public function syncRolesAs(User $editor, User $target, Collection $roleIds): void
    {
        if ($denial = $this->roleSyncDenial($editor, $target, $target->organization_id, $roleIds)) {
            throw ValidationException::withMessages(['roles' => $denial]);
        }

        $current = $this->assignedRoleIds($target);
        $removed = $current->diff($roleIds);
        $added = Role::whereKey($roleIds->diff($current))->get();

        DB::transaction(function () use ($target, $removed, $added): void {
            DB::table('model_has_roles')
                ->where('model_type', $target->getMorphClass())
                ->where('model_id', $target->id)
                ->whereIn('role_id', $removed)
                ->delete();

            DB::table('model_has_roles')->insert($added->map(fn (Role $role) => [
                'role_id' => $role->id,
                'model_type' => $target->getMorphClass(),
                'model_id' => $target->id,
                'organization_id' => $role->organization_id,
            ])->all());
        });

        app(PermissionRegistrar::class)->forgetCachedPermissions();
        $target->unsetRelation('roles');
    }

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
     * The role with this name (case-insensitive) that the caller may grant to a member of the organization, if any.
     */
    public function findAssignableRole(User $caller, ?int $organizationId, string $name, ?string $guard = null): ?Role
    {
        return Role::query()
            ->whereRaw('LOWER(name) = LOWER(?)', [$name])
            ->when($guard !== null, fn (Builder $query) => $query->where('guard_name', $guard))
            ->where(fn (Builder $query) => $this->scopeToAssignableRoles($query, $caller, $organizationId))
            ->first();
    }

    public function canGrantRoleNamed(User $caller, ?int $organizationId, string $name): bool
    {
        $role = $this->findAssignableRole($caller, $organizationId, $name);

        return $role !== null && $this->roleChangeDenial($caller, null, new EloquentCollection([$role])) === null;
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

        $rolePermissions = $roles->load('permissions')->flatMap(fn (Role $role) => $role->permissions->pluck('name'));

        return $this->exceedsPermissionsOf($caller, $rolePermissions)
            ? 'You cannot grant or revoke a role with permissions you do not have.'
            : null;
    }

    /**
     * @param  Collection<int, string>  $permissionNames
     */
    public function exceedsPermissionsOf(User $caller, Collection $permissionNames): bool
    {
        if ($caller->isSuperAdmin()) {
            return false;
        }

        return $permissionNames->diff($this->effectivePermissionNames($caller))->isNotEmpty();
    }

    /**
     * Permission names granted through Spatie roles, direct permissions and active custom roles.
     *
     * @return Collection<int, string>
     */
    public function effectivePermissionNames(User $user): Collection
    {
        return $user->getAllPermissions()->pluck('name')
            ->merge($user->customRoles()
                ->where('is_active', true)
                ->where('custom_roles.organization_id', $user->organization_id)
                ->get()->pluck('permissions')->flatten())
            ->unique()
            ->values();
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
