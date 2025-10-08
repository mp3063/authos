<?php

namespace Tests\Feature\Webhooks;

use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Jobs\DeliverWebhookJob;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class WebhookEventsTest extends TestCase
{
    private Organization $organization;

    private Webhook $webhook;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['*']]);
    }

    public function test_dispatches_user_created_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'user.created';
        });
    }

    public function test_dispatches_user_updated_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();
        $user->name = 'Updated Name';
        $user->save();

        Event::dispatch(new UserUpdatedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'user.updated';
        });
    }

    public function test_dispatches_user_deleted_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserDeletedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'user.deleted';
        });
    }

    public function test_dispatches_auth_login_event(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['auth.login']]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new \App\Events\AuthLoginEvent($user, '127.0.0.1'));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'auth.login';
        });
    }

    public function test_dispatches_auth_failed_event(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['auth.failed']]);

        Event::dispatch(new \App\Events\AuthFailedEvent('user@example.com', '127.0.0.1', $this->organization->id));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'auth.failed';
        });
    }

    public function test_dispatches_mfa_enabled_event(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['mfa.enabled']]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new \App\Events\MfaEnabledEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'mfa.enabled';
        });
    }

    public function test_dispatches_application_created_event(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['application.created']]);

        $application = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        Event::dispatch(new \App\Events\ApplicationCreatedEvent($application));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'application.created';
        });
    }

    public function test_dispatches_organization_updated_event(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['organization.updated']]);

        $this->organization->name = 'Updated Organization';
        $this->organization->save();

        Event::dispatch(new \App\Events\OrganizationUpdatedEvent($this->organization));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->payload['event'] === 'organization.updated';
        });
    }

    public function test_only_dispatches_to_subscribed_events(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['user.created']]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));
        Event::dispatch(new UserUpdatedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, 1);
    }

    public function test_wildcard_event_receives_all_events(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['*']]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));
        Event::dispatch(new UserUpdatedEvent($user));
        Event::dispatch(new UserDeletedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, 3);
    }

    public function test_pattern_event_subscription(): void
    {
        Queue::fake();

        $this->webhook->update(['events' => ['user.*']]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));
        Event::dispatch(new UserUpdatedEvent($user));
        Event::dispatch(new \App\Events\AuthLoginEvent($user, '127.0.0.1'));

        Queue::assertPushed(DeliverWebhookJob::class, 2);
    }

    public function test_event_payload_includes_metadata(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            $payload = $job->payload;

            return isset($payload['event'])
                && isset($payload['data'])
                && isset($payload['timestamp'])
                && isset($payload['id'])
                && isset($payload['organization_id']);
        });
    }

    public function test_event_payload_excludes_sensitive_data(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create([
            'password' => bcrypt('secret123'),
            'two_factor_secret' => 'mfa-secret',
        ]);

        Event::dispatch(new UserCreatedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            $data = $job->payload['data'];

            return ! isset($data['password'])
                && ! isset($data['two_factor_secret'])
                && ! isset($data['remember_token']);
        });
    }

    public function test_does_not_dispatch_to_inactive_webhooks(): void
    {
        Queue::fake();

        $this->webhook->update(['is_active' => false]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));

        Queue::assertNotPushed(DeliverWebhookJob::class);
    }

    public function test_does_not_dispatch_to_other_organizations(): void
    {
        Queue::fake();

        $org2 = Organization::factory()->create();
        $webhook2 = Webhook::factory()
            ->for($org2)
            ->create(['events' => ['*']]);

        $user = User::factory()->for($this->organization)->create();

        Event::dispatch(new UserCreatedEvent($user));

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) {
            return $job->webhook->organization_id === $this->organization->id;
        });

        Queue::assertPushed(DeliverWebhookJob::class, 1);
    }
}
