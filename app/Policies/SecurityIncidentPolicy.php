<?php

namespace App\Policies;

use App\Models\SecurityIncident;
use App\Models\User;

class SecurityIncidentPolicy
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
    public function view(User $user, SecurityIncident $securityIncident): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Incidents with a user_id are scoped to the user's org
        if ($securityIncident->user_id) {
            return $user->organization_id === $securityIncident->user?->organization_id
                && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
        }

        // Incidents without a user (IP-based) are super admin only
        return false;
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // Security incidents are system-generated
        return false;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, SecurityIncident $securityIncident): bool
    {
        // Admins can resolve/dismiss incidents in their org
        if ($user->isSuperAdmin()) {
            return true;
        }

        if ($securityIncident->user_id) {
            return $user->organization_id === $securityIncident->user?->organization_id
                && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
        }

        return false;
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SecurityIncident $securityIncident): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, SecurityIncident $securityIncident): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user, SecurityIncident $securityIncident): bool
    {
        return $user->isSuperAdmin();
    }
}
