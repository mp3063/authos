<?php

namespace App\Policies;

use App\Models\BulkImportJob;
use App\Models\User;

class BulkImportJobPolicy
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
    public function view(User $user, BulkImportJob $bulkImportJob): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $bulkImportJob->organization_id
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

        return $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, BulkImportJob $bulkImportJob): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $bulkImportJob->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, BulkImportJob $bulkImportJob): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $bulkImportJob->organization_id
            && $user->hasRole('Organization Owner');
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
    public function forceDelete(User $user, BulkImportJob $bulkImportJob): bool
    {
        return $user->isSuperAdmin();
    }
}
