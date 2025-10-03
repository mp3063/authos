<?php

namespace App\Policies;

use App\Models\CustomDomain;
use App\Models\User;

class CustomDomainPolicy
{
    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        // Super admins can view all custom domains
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners and admins can view their org's domains
        return $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, CustomDomain $customDomain): bool
    {
        // Super admins can view all domains
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can only view domains from their organization
        return $user->organization_id === $customDomain->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // Super admins can create for any organization
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners can create custom domains
        return $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, CustomDomain $customDomain): bool
    {
        // Super admins can update any domain
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners can update their org's domains
        return $user->organization_id === $customDomain->organization_id
            && $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, CustomDomain $customDomain): bool
    {
        // Super admins can delete any domain
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners can delete their org's domains
        return $user->organization_id === $customDomain->organization_id
            && $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, CustomDomain $customDomain): bool
    {
        return $this->delete($user, $customDomain);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, CustomDomain $customDomain): bool
    {
        // Only super admins can force delete
        return $user->isSuperAdmin();
    }
}
