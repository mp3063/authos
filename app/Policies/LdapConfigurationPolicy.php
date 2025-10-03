<?php

namespace App\Policies;

use App\Models\LdapConfiguration;
use App\Models\User;

class LdapConfigurationPolicy
{
    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        // Super admins can view all LDAP configurations
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners and admins can view their org's configurations
        return $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, LdapConfiguration $ldapConfiguration): bool
    {
        // Super admins can view all configurations
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can only view configurations from their organization
        return $user->organization_id === $ldapConfiguration->organization_id
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

        // Organization owners can create LDAP configurations
        return $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, LdapConfiguration $ldapConfiguration): bool
    {
        // Super admins can update any configuration
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners can update their org's configurations
        return $user->organization_id === $ldapConfiguration->organization_id
            && $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, LdapConfiguration $ldapConfiguration): bool
    {
        // Super admins can delete any configuration
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners can delete their org's configurations
        return $user->organization_id === $ldapConfiguration->organization_id
            && $user->hasRole('Organization Owner');
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, LdapConfiguration $ldapConfiguration): bool
    {
        return $this->delete($user, $ldapConfiguration);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, LdapConfiguration $ldapConfiguration): bool
    {
        // Only super admins can force delete
        return $user->isSuperAdmin();
    }
}
