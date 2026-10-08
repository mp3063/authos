<?php

namespace App\Policies;

use App\Models\User;
use App\Models\WebhookDelivery;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class WebhookDeliveryPolicy
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
    public function view(User $user, WebhookDelivery $webhookDelivery): bool
    {
        return $this->permits($user, 'webhooks.read', $webhookDelivery->webhook?->organization_id);
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
    public function update(User $user, WebhookDelivery $webhookDelivery): bool
    {
        return $this->permits($user, 'webhooks.update', $webhookDelivery->webhook?->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, WebhookDelivery $webhookDelivery): bool
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
    public function restore(User $user, WebhookDelivery $webhookDelivery): bool
    {
        return $this->delete($user, $webhookDelivery);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
