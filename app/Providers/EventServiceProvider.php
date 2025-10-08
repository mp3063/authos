<?php

namespace App\Providers;

use App\Events\ApplicationCreatedEvent;
use App\Events\AuthFailedEvent;
use App\Events\AuthLoginEvent;
use App\Events\MfaEnabledEvent;
use App\Events\OrganizationUpdatedEvent;
use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Listeners\WebhookEventSubscriber;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    /**
     * The event to listener mappings for the application.
     *
     * @var array<class-string, array<int, class-string>>
     */
    protected $listen = [
        UserCreatedEvent::class => [
            WebhookEventSubscriber::class.'@handleUserCreated',
        ],
        UserUpdatedEvent::class => [
            WebhookEventSubscriber::class.'@handleUserUpdated',
        ],
        UserDeletedEvent::class => [
            WebhookEventSubscriber::class.'@handleUserDeleted',
        ],
        AuthLoginEvent::class => [
            WebhookEventSubscriber::class.'@handleAuthLogin',
        ],
        AuthFailedEvent::class => [
            WebhookEventSubscriber::class.'@handleAuthFailed',
        ],
        MfaEnabledEvent::class => [
            WebhookEventSubscriber::class.'@handleMfaEnabled',
        ],
        ApplicationCreatedEvent::class => [
            WebhookEventSubscriber::class.'@handleApplicationCreated',
        ],
        OrganizationUpdatedEvent::class => [
            WebhookEventSubscriber::class.'@handleOrganizationUpdated',
        ],
    ];

    /**
     * The subscriber classes to register.
     *
     * @var array<int, class-string>
     */
    protected $subscribe = [
        // Moved to $listen array above for better control
    ];

    /**
     * Register any events for your application.
     */
    public function boot(): void
    {
        parent::boot();
    }

    /**
     * Determine if events and listeners should be automatically discovered.
     */
    public function shouldDiscoverEvents(): bool
    {
        return false;
    }
}
