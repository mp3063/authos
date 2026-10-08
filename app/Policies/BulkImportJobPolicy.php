<?php

namespace App\Policies;

use App\Models\BulkImportJob;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class BulkImportJobPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'users.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, BulkImportJob $bulkImportJob): bool
    {
        return $this->permits($user, 'users.read', $bulkImportJob->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'users.create', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, BulkImportJob $bulkImportJob): bool
    {
        return $this->permits($user, 'users.create', $bulkImportJob->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, BulkImportJob $bulkImportJob): bool
    {
        return $this->permits($user, 'users.delete', $bulkImportJob->organization_id);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'users.delete', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, BulkImportJob $bulkImportJob): bool
    {
        return $this->delete($user, $bulkImportJob);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
