<?php

namespace Tests\Integration\Events;

use App\Events\Auth\LoginAttempted;
use App\Events\Auth\LoginSuccessful;
use App\Events\UserCreatedEvent;
use App\Listeners\Auth\CheckAccountLockout;
use App\Listeners\Auth\CheckIpBlocklist;
use App\Listeners\Auth\RegenerateSession;
use App\Listeners\Auth\SendNewDeviceLoginAlert;
use App\Listeners\WebhookEventSubscriber;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class EventListenerRegistrationTest extends TestCase
{
    #[Test]
    public function no_application_listener_is_registered_twice(): void
    {
        $duplicates = collect(app('events')->getRawListeners())
            ->filter(fn ($listeners, $event) => Str::startsWith($event, 'App\\Events\\'))
            ->map(fn ($listeners) => collect($listeners)
                ->filter(fn ($listener) => is_string($listener))
                ->map(fn ($listener) => Str::before($listener, '@handle'))
                ->duplicates()
                ->values()
                ->all())
            ->filter();

        $this->assertSame([], $duplicates->all());
    }

    #[Test]
    public function security_listeners_run_once_in_declared_order(): void
    {
        $listeners = app('events')->getRawListeners();

        $this->assertSame([CheckIpBlocklist::class, CheckAccountLockout::class], $listeners[LoginAttempted::class]);
        $this->assertSame([RegenerateSession::class, SendNewDeviceLoginAlert::class], $listeners[LoginSuccessful::class]);
        $this->assertSame([WebhookEventSubscriber::class.'@handleUserCreated'], $listeners[UserCreatedEvent::class]);
    }
}
