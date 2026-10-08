<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Webhook;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class WebhookPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'webhooks.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, Webhook $webhook): bool
    {
        return $this->permits($user, 'webhooks.read', $webhook->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'webhooks.create', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, Webhook $webhook): bool
    {
        return $this->permits($user, 'webhooks.update', $webhook->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, Webhook $webhook): bool
    {
        return $this->permits($user, 'webhooks.delete', $webhook->organization_id);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'webhooks.delete', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, Webhook $webhook): bool
    {
        return $this->delete($user, $webhook);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
