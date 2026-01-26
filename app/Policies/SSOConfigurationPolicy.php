<?php

namespace App\Policies;

use App\Models\SSOConfiguration;
use App\Models\User;

class SSOConfigurationPolicy
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
    public function view(User $user, SSOConfiguration $ssoConfiguration): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $ssoConfiguration->application?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, SSOConfiguration $ssoConfiguration): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $ssoConfiguration->application?->organization_id
            && $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SSOConfiguration $ssoConfiguration): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $ssoConfiguration->application?->organization_id
            && $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, SSOConfiguration $ssoConfiguration): bool
    {
        return $this->delete($user, $ssoConfiguration);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, SSOConfiguration $ssoConfiguration): bool
    {
        return $user->isSuperAdmin();
    }
}
