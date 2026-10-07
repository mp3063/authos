<?php

namespace App\Listeners;

use App\Events\AuthFailedEvent;
use App\Events\AuthLoginEvent;
use App\Events\MfaDisabledEvent;
use App\Events\MfaEnabledEvent;
use App\Events\OrganizationSettingsChangedEvent;
use App\Events\OrganizationUpdatedEvent;
use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Listeners\Concerns\DispatchesWebhooks;

class WebhookEventSubscriber
{
    use DispatchesWebhooks;

    /**
     * Handle user created event
     */
    public function handleUserCreated(UserCreatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->user->organization_id);
    }

    /**
     * Handle user updated event
     */
    public function handleUserUpdated(UserUpdatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->user->organization_id);
    }

    /**
     * Handle user deleted event
     */
    public function handleUserDeleted(UserDeletedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->user->organization_id);
    }

    /**
     * Handle auth login event
     */
    public function handleAuthLogin(AuthLoginEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->user->organization_id);
    }

    /**
     * Handle auth failed event
     */
    public function handleAuthFailed(AuthFailedEvent $event): void
    {
        // Auth failed events might not have organization context
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->organizationId ?? null);
    }

    /**
     * Handle MFA enabled event
     */
    public function handleMfaEnabled(MfaEnabledEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->user->organization_id);
    }

    /**
     * Handle organization updated event
     */
    public function handleOrganizationUpdated(OrganizationUpdatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->organization->id);
    }

    public function handleOrganizationSettingsChanged(OrganizationSettingsChangedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->organization->id);
    }

    public function handleMfaDisabled(MfaDisabledEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->user->organization_id);
    }
}
