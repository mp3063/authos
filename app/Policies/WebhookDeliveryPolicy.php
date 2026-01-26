<?php

namespace App\Policies;

use App\Models\User;
use App\Models\WebhookDelivery;

class WebhookDeliveryPolicy
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
    public function view(User $user, WebhookDelivery $webhookDelivery): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $webhookDelivery->webhook?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        // Webhook deliveries are created by the system, not manually
        return $user->isSuperAdmin();
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, WebhookDelivery $webhookDelivery): bool
    {
        // Deliveries are system-managed; admins can retry
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $webhookDelivery->webhook?->organization_id
            && $user->hasAnyRole(['Organization Owner', 'Organization Admin']);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, WebhookDelivery $webhookDelivery): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        return $user->organization_id === $webhookDelivery->webhook?->organization_id
            && $user->hasRole('Organization Owner');
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
    public function forceDelete(User $user, WebhookDelivery $webhookDelivery): bool
    {
        return $user->isSuperAdmin();
    }
}
