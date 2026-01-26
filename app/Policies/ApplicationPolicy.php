<?php

namespace App\Policies;

use App\Models\Application;
use App\Models\User;

class ApplicationPolicy
{
    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, Application $application): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $application->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, Application $application): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $application->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, Application $application): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $application->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, Application $application): bool
    {
        return $this->delete($user, $application);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, Application $application): bool
    {
        return $user->isSuperAdmin();
    }
}
