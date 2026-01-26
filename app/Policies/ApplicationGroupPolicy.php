<?php

namespace App\Policies;

use App\Models\ApplicationGroup;
use App\Models\User;

class ApplicationGroupPolicy
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
    public function view(User $user, ApplicationGroup $applicationGroup): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $applicationGroup->organization_id
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
    public function update(User $user, ApplicationGroup $applicationGroup): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $applicationGroup->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, ApplicationGroup $applicationGroup): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $applicationGroup->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, ApplicationGroup $applicationGroup): bool
    {
        return $this->delete($user, $applicationGroup);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, ApplicationGroup $applicationGroup): bool
    {
        return $user->isSuperAdmin();
    }
}
