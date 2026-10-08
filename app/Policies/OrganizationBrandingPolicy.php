<?php

namespace App\Policies;

use App\Models\OrganizationBranding;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class OrganizationBrandingPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'organizations.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, OrganizationBranding $organizationBranding): bool
    {
        return $this->permits($user, 'organizations.read', $organizationBranding->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'organizations.update', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, OrganizationBranding $organizationBranding): bool
    {
        return $this->permits($user, 'organizations.update', $organizationBranding->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, OrganizationBranding $organizationBranding): bool
    {
        return $this->permits($user, 'organizations.update', $organizationBranding->organization_id);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'organizations.update', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, OrganizationBranding $organizationBranding): bool
    {
        return $this->delete($user, $organizationBranding);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
