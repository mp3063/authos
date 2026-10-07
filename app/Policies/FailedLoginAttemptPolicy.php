<?php

namespace App\Policies;

use App\Models\User;

class FailedLoginAttemptPolicy
{
    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user): bool
    {
        // Failed login attempts are global (IP/email based), not org-scoped
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(): bool
    {
        // System-generated records
        return false;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(): bool
    {
        // Immutable audit records
        return false;
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
