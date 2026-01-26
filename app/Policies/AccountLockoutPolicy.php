<?php

namespace App\Policies;

use App\Models\AccountLockout;
use App\Models\User;

class AccountLockoutPolicy
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
    public function view(User $user, AccountLockout $accountLockout): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        if ($accountLockout->user_id) {
            return $user->organization_id === $accountLockout->user?->organization_id
                && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
        }

        return false;
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // Lockouts are system-generated
        return false;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, AccountLockout $accountLockout): bool
    {
        // Admins can unlock accounts in their org
        if ($user->isSuperAdmin()) {
            return true;
        }

        if ($accountLockout->user_id) {
            return $user->organization_id === $accountLockout->user?->organization_id
                && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
        }

        return false;
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, AccountLockout $accountLockout): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, AccountLockout $accountLockout): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, AccountLockout $accountLockout): bool
    {
        return $user->isSuperAdmin();
    }
}
