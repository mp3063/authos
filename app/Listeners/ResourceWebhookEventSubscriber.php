<?php

namespace App\Listeners;

use App\Events\ApplicationCreatedEvent;
use App\Events\ApplicationDeletedEvent;
use App\Events\ApplicationUpdatedEvent;
use App\Events\DomainVerifiedEvent;
use App\Events\RoleCreatedEvent;
use App\Events\RoleDeletedEvent;
use App\Events\RoleUpdatedEvent;
use App\Events\WebhookCreatedEvent;
use App\Events\WebhookDeletedEvent;
use App\Events\WebhookUpdatedEvent;
use App\Listeners\Concerns\DispatchesWebhooks;

class ResourceWebhookEventSubscriber
{
    use DispatchesWebhooks;

    /**
     * Handle application created event
     */
    public function handleApplicationCreated(ApplicationCreatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->application->organization_id);
    }

    public function handleApplicationUpdated(ApplicationUpdatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->application->organization_id);
    }

    public function handleApplicationDeleted(ApplicationDeletedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->application->organization_id);
    }

    public function handleRoleCreated(RoleCreatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->role->organization_id);
    }

    public function handleRoleUpdated(RoleUpdatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->role->organization_id);
    }

    public function handleRoleDeleted(RoleDeletedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->role->organization_id);
    }

    public function handleWebhookCreated(WebhookCreatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->webhook->organization_id);
    }

    public function handleWebhookUpdated(WebhookUpdatedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->webhook->organization_id);
    }

    public function handleWebhookDeleted(WebhookDeletedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->webhook->organization_id);
    }

    public function handleDomainVerified(DomainVerifiedEvent $event): void
    {
        $this->dispatchWebhooks($event->getEventType(), $event->getPayload(), $event->domain->organization_id);
    }
}
