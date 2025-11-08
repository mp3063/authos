<?php

namespace App\Providers;

use App\Events\ApplicationCreatedEvent;
use App\Events\Auth\LoginAttempted;
use App\Events\Auth\LoginFailed;
use App\Events\Auth\LoginSuccessful;
use App\Events\AuthFailedEvent;
use App\Events\AuthLoginEvent;
use App\Events\MfaEnabledEvent;
use App\Events\OrganizationUpdatedEvent;
use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Listeners\Auth\CheckAccountLockout;
use App\Listeners\Auth\CheckIpBlocklist;
use App\Listeners\Auth\RecordFailedLoginAttempt;
use App\Listeners\Auth\RegenerateSession;
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
            // NOTE: Both RecordFailedLoginAttempt and TriggerIntrusionDetection are auto-discovered by Laravel
            // based on type hints. Removed from here to prevent duplicate registration.
        ],
        LoginSuccessful::class => [
            RegenerateSession::class,      // Clear failed attempts and security cleanup
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
