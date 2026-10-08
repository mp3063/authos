<?php

namespace App\Policies;

use App\Models\ApplicationGroup;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class ApplicationGroupPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'applications.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, ApplicationGroup $applicationGroup): bool
    {
        return $this->permits($user, 'applications.read', $applicationGroup->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'applications.create', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, ApplicationGroup $applicationGroup): bool
    {
        return $this->permits($user, 'applications.update', $applicationGroup->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, ApplicationGroup $applicationGroup): bool
    {
        return $this->permits($user, 'applications.delete', $applicationGroup->organization_id);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'applications.delete', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, ApplicationGroup $applicationGroup): bool
    {
        return $this->delete($user, $applicationGroup);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
