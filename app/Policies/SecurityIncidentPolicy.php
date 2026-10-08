<?php

namespace App\Policies;

use App\Models\SecurityIncident;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class SecurityIncidentPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'auth_logs.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, SecurityIncident $securityIncident): bool
    {
        return $this->permits($user, 'auth_logs.read', $this->organizationIdOf($securityIncident));
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return false;
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, SecurityIncident $securityIncident): bool
    {
        return $this->permits($user, 'organizations.update', $this->organizationIdOf($securityIncident));
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SecurityIncident $securityIncident): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, SecurityIncident $securityIncident): bool
    {
        return $this->delete($user, $securityIncident);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    private function organizationIdOf(SecurityIncident $securityIncident): ?int
    {
        return $securityIncident->organization_id ?? $securityIncident->user?->organization_id;
    }
}
