<?php

namespace App\Policies;

use App\Models\SocialAccount;
use App\Models\User;

class SocialAccountPolicy
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
    public function view(User $user, SocialAccount $socialAccount): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can view their own social accounts
        if ($user->id === $socialAccount->user_id) {
            return true;
        }

        return $user->organization_id === $socialAccount->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // Social accounts are created through OAuth flow
        return true;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, SocialAccount $socialAccount): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can update their own social accounts
        if ($user->id === $socialAccount->user_id) {
            return true;
        }

        return $user->organization_id === $socialAccount->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SocialAccount $socialAccount): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can unlink their own social accounts
        if ($user->id === $socialAccount->user_id) {
            return true;
        }

        return $user->organization_id === $socialAccount->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, SocialAccount $socialAccount): bool
    {
        return $this->delete($user, $socialAccount);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, SocialAccount $socialAccount): bool
    {
        return $user->isSuperAdmin();
    }
}
