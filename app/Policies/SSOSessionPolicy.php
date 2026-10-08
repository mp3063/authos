<?php

namespace App\Policies;

use App\Models\SSOSession;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class SSOSessionPolicy
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
    public function view(User $user, SSOSession $ssoSession): bool
    {
        return $user->id === $ssoSession->user_id
            || $this->permits($user, 'auth_logs.read', $ssoSession->user?->organization_id);
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
    public function update(User $user, SSOSession $ssoSession): bool
    {
        return $user->id === $ssoSession->user_id
            || $this->permits($user, 'users.update', $ssoSession->user?->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SSOSession $ssoSession): bool
    {
        return $this->update($user, $ssoSession);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'users.update', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, SSOSession $ssoSession): bool
    {
        return $this->delete($user, $ssoSession);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
