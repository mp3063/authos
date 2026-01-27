<?php

namespace App\Providers;

use App\Events\ApplicationCreatedEvent;
use App\Events\ApplicationDeletedEvent;
use App\Events\ApplicationUpdatedEvent;
use App\Events\Auth\LoginAttempted;
use App\Events\Auth\LoginFailed;
use App\Events\Auth\LoginSuccessful;
use App\Events\AuthFailedEvent;
use App\Events\AuthLoginEvent;
use App\Events\DomainVerifiedEvent;
use App\Events\MfaDisabledEvent;
use App\Events\MfaEnabledEvent;
use App\Events\OrganizationSettingsChangedEvent;
use App\Events\OrganizationUpdatedEvent;
use App\Events\RoleCreatedEvent;
use App\Events\RoleDeletedEvent;
use App\Events\RoleUpdatedEvent;
use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Events\WebhookCreatedEvent;
use App\Events\WebhookDeletedEvent;
use App\Events\WebhookUpdatedEvent;
use App\Listeners\Auth\CheckAccountLockout;
use App\Listeners\Auth\CheckIpBlocklist;
use App\Listeners\Auth\RecordFailedLoginAttempt;
use App\Listeners\Auth\RegenerateSession;
use App\Listeners\Auth\SendNewDeviceLoginAlert;
use App\Listeners\Auth\TriggerIntrusionDetection;
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
        // Authentication Security Events (executed in order)
        LoginAttempted::class => [
            CheckIpBlocklist::class,      // First: Check if IP is blocked
            CheckAccountLockout::class,    // Second: Check if account is locked
        ],
        LoginFailed::class => [
            RecordFailedLoginAttempt::class,    // First: Record the failed attempt in database
            TriggerIntrusionDetection::class,    // Second: Analyze attempts and apply countermeasures
        ],
        LoginSuccessful::class => [
            RegenerateSession::class,          // Clear failed attempts and security cleanup
            SendNewDeviceLoginAlert::class,    // Alert user about new device login
        ],

        // Webhook Events
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
        ApplicationUpdatedEvent::class => [
            WebhookEventSubscriber::class.'@handleApplicationUpdated',
        ],
        ApplicationDeletedEvent::class => [
            WebhookEventSubscriber::class.'@handleApplicationDeleted',
        ],
        OrganizationUpdatedEvent::class => [
            WebhookEventSubscriber::class.'@handleOrganizationUpdated',
        ],
        OrganizationSettingsChangedEvent::class => [
            WebhookEventSubscriber::class.'@handleOrganizationSettingsChanged',
        ],
        RoleCreatedEvent::class => [
            WebhookEventSubscriber::class.'@handleRoleCreated',
        ],
        RoleUpdatedEvent::class => [
            WebhookEventSubscriber::class.'@handleRoleUpdated',
        ],
        RoleDeletedEvent::class => [
            WebhookEventSubscriber::class.'@handleRoleDeleted',
        ],
        WebhookCreatedEvent::class => [
            WebhookEventSubscriber::class.'@handleWebhookCreated',
        ],
        WebhookUpdatedEvent::class => [
            WebhookEventSubscriber::class.'@handleWebhookUpdated',
        ],
        WebhookDeletedEvent::class => [
            WebhookEventSubscriber::class.'@handleWebhookDeleted',
        ],
        DomainVerifiedEvent::class => [
            WebhookEventSubscriber::class.'@handleDomainVerified',
        ],
        MfaDisabledEvent::class => [
            WebhookEventSubscriber::class.'@handleMfaDisabled',
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

    /**
     * Get the listener directories that should be used to discover events.
     *
     * Returning an empty array prevents auto-discovery of listeners.
     */
    protected function discoverEventsWithin(): array
    {
        return [];
    }
}
