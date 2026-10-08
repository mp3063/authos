<?php

namespace App\Policies;

use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;
use App\Services\UserRoleService;
use Spatie\Permission\PermissionRegistrar;

class UserPolicy
{
    use ChecksOrganizationPermissions;

    public function __construct(private UserRoleService $userRoleService) {}

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'users.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, User $model): bool
    {
        return $user->id === $model->id
            || $this->permits($user, 'users.read', $model->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'users.create', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, User $model): bool
    {
        return $user->id === $model->id
            || $this->permitsOnTarget($user, 'users.update', $model);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, User $model): bool
    {
        return $user->id !== $model->id
            && $this->permitsOnTarget($user, 'users.delete', $model);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'users.delete', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, User $model): bool
    {
        return $this->delete($user, $model);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    private function permitsOnTarget(User $user, string $permission, User $model): bool
    {
        return $this->permits($user, $permission, $model->organization_id)
            && ! $this->targetExceedsUser($user, $model);
    }

    private function targetExceedsUser(User $user, User $model): bool
    {
        if ($model->isSuperAdmin()) {
            return ! $user->isSuperAdmin();
        }

        $registrar = app(PermissionRegistrar::class);
        $previousTeamId = $registrar->getPermissionsTeamId();
        $userRelations = $user->getRelations();
        $modelRelations = $model->getRelations();
        $registrar->setPermissionsTeamId($model->organization_id);

        try {
            $user->unsetRelation('roles')->load('permissions');
            $model->unsetRelation('roles')->load('permissions');

            return $this->userRoleService->exceedsPermissionsOf($user, $this->userRoleService->effectivePermissionNames($model));
        } finally {
            $registrar->setPermissionsTeamId($previousTeamId);
            $user->setRelations($userRelations);
            $model->setRelations($modelRelations);
        }
    }
}
