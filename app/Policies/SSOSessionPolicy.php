<?php

namespace App\Policies;

use App\Models\SSOSession;
use App\Models\User;

class SSOSessionPolicy
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
    public function view(User $user, SSOSession $ssoSession): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can view their own sessions
        if ($user->id === $ssoSession->user_id) {
            return true;
        }

        return $user->organization_id === $ssoSession->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // SSO sessions are created by the system during authentication
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, SSOSession $ssoSession): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $ssoSession->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SSOSession $ssoSession): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can terminate their own sessions
        if ($user->id === $ssoSession->user_id) {
            return true;
        }

        return $user->organization_id === $ssoSession->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, SSOSession $ssoSession): bool
    {
        return $this->delete($user, $ssoSession);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, SSOSession $ssoSession): bool
    {
        return $user->isSuperAdmin();
    }
}
