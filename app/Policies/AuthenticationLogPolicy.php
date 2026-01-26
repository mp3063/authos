<?php

namespace App\Policies;

use App\Models\AuthenticationLog;
use App\Models\User;

class AuthenticationLogPolicy
{
    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Auditor']);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, AuthenticationLog $authenticationLog): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can view their own authentication logs
        if ($user->id === $authenticationLog->user_id) {
            return true;
        }

        return $user->organization_id === $authenticationLog->user?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin', 'Auditor']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // Authentication logs are system-generated
        return false;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, AuthenticationLog $authenticationLog): bool
    {
        // Authentication logs are immutable audit records
        return false;
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, AuthenticationLog $authenticationLog): bool
    {
        // Only super admins can delete audit logs
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, AuthenticationLog $authenticationLog): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, AuthenticationLog $authenticationLog): bool
    {
        return $user->isSuperAdmin();
    }
}
