<?php

namespace App\Policies;

use App\Models\User;
use App\Models\UserApplication;

class UserApplicationPolicy
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
    public function view(User $user, UserApplication $userApplication): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can view their own application assignments
        if ($user->id === $userApplication->user_id) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
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
    public function update(User $user, UserApplication $userApplication): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Application Manager']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, UserApplication $userApplication): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
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
    public function forceDelete(User $user, UserApplication $userApplication): bool
    {
        return $user->isSuperAdmin();
    }
}
