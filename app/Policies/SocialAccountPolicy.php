<?php

namespace App\Policies;

use App\Models\SocialAccount;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class SocialAccountPolicy
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
    public function view(User $user, SocialAccount $socialAccount): bool
    {
        return $user->id === $socialAccount->user_id
            || $this->permits($user, 'users.read', $socialAccount->user?->organization_id);
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
    public function update(User $user, SocialAccount $socialAccount): bool
    {
        return $user->isSuperAdmin() || $user->id === $socialAccount->user_id;
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, SocialAccount $socialAccount): bool
    {
        return $user->id === $socialAccount->user_id
            || $this->permits($user, 'users.update', $socialAccount->user?->organization_id);
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
    public function restore(User $user, SocialAccount $socialAccount): bool
    {
        return $this->delete($user, $socialAccount);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
