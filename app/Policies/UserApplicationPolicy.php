<?php

namespace App\Policies;

use App\Models\Application;
use App\Models\User;
use App\Models\UserApplication;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class UserApplicationPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'applications.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, UserApplication $userApplication): bool
    {
        return $user->id === $userApplication->user_id
            || $this->permits($user, 'applications.read', $this->applicationOrganizationId($userApplication));
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'applications.update', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, UserApplication $userApplication): bool
    {
        return $this->permits($user, 'applications.update', $this->applicationOrganizationId($userApplication));
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, UserApplication $userApplication): bool
    {
        return $this->update($user, $userApplication);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->create($user);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, UserApplication $userApplication): bool
    {
        return $this->delete($user, $userApplication);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    private function applicationOrganizationId(UserApplication $userApplication): ?int
    {
        return Application::query()->whereKey($userApplication->application_id)->value('organization_id');
    }
}
