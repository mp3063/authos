<?php

namespace App\Policies;

use App\Models\MigrationJob;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class MigrationJobPolicy
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
    public function view(User $user, MigrationJob $migrationJob): bool
    {
        return $this->permits($user, 'organizations.read', $migrationJob->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, MigrationJob $migrationJob): bool
    {
        return $this->permits($user, 'organizations.update', $migrationJob->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, MigrationJob $migrationJob): bool
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
    public function restore(User $user, MigrationJob $migrationJob): bool
    {
        return $this->delete($user, $migrationJob);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
