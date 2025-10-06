<?php

namespace Tests\Unit\Services;

use App\Events\UserCreatedEvent;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Services\WebhookEventDispatcher;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class WebhookEventDispatcherTest extends TestCase
{
    private WebhookEventDispatcher $dispatcher;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dispatcher = new WebhookEventDispatcher;
        $this->organization = Organization::factory()->create();
    }

    public function test_dispatches_user_created_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.created']]);

        Event::dispatch(new UserCreatedEvent($user));

        $this->dispatcher->handleUserCreated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class, function ($job) use ($webhook) {
            return $job->webhook->id === $webhook->id;
        });
    }

    public function test_dispatches_user_updated_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.updated']]);

        $this->dispatcher->handleUserUpdated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class);
    }

    public function test_dispatches_user_deleted_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.deleted']]);

        $this->dispatcher->handleUserDeleted($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class);
    }

    public function test_extracts_organization_from_user(): void
    {
        $user = User::factory()->for($this->organization)->create();

        $organizationId = $this->dispatcher->extractOrganizationId($user);

        $this->assertEquals($this->organization->id, $organizationId);
    }

    public function test_extracts_organization_from_model_with_organization(): void
    {
        $model = new class
        {
            public $organization_id = 123;
        };

        $organizationId = $this->dispatcher->extractOrganizationId($model);

        $this->assertEquals(123, $organizationId);
    }

    public function test_removes_sensitive_fields(): void
    {
        $user = User::factory()->for($this->organization)->create([
            'password' => bcrypt('secret123'),
            'remember_token' => 'token123',
            'two_factor_secret' => 'secret456',
        ]);

        $payload = $this->dispatcher->buildUserPayload($user);

        $this->assertArrayNotHasKey('password', $payload['data']);
        $this->assertArrayNotHasKey('remember_token', $payload['data']);
        $this->assertArrayNotHasKey('two_factor_secret', $payload['data']);
        $this->assertArrayNotHasKey('two_factor_recovery_codes', $payload['data']);
    }

    public function test_builds_payload_with_event_metadata(): void
    {
        $user = User::factory()->for($this->organization)->create();

        $payload = $this->dispatcher->buildUserPayload($user, 'user.created');

        $this->assertArrayHasKey('event', $payload);
        $this->assertEquals('user.created', $payload['event']);
        $this->assertArrayHasKey('data', $payload);
        $this->assertArrayHasKey('timestamp', $payload);
        $this->assertArrayHasKey('id', $payload);
        $this->assertIsString($payload['id']);
    }

    public function test_includes_organization_context(): void
    {
        $user = User::factory()->for($this->organization)->create();

        $payload = $this->dispatcher->buildUserPayload($user);

        $this->assertArrayHasKey('organization_id', $payload);
        $this->assertEquals($this->organization->id, $payload['organization_id']);
    }

    public function test_does_not_dispatch_to_other_organizations(): void
    {
        Queue::fake();

        $org1 = $this->organization;
        $org2 = Organization::factory()->create();

        $user = User::factory()->for($org1)->create();

        // Create webhook for org1
        Webhook::factory()
            ->for($org1)
            ->create(['events' => ['user.created']]);

        // Create webhook for org2 (should not receive event)
        Webhook::factory()
            ->for($org2)
            ->create(['events' => ['user.created']]);

        $this->dispatcher->handleUserCreated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class, 1);
    }

    public function test_only_dispatches_to_active_webhooks(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Webhook::factory()
            ->for($this->organization)
            ->create([
                'events' => ['user.created'],
                'is_active' => true,
            ]);

        Webhook::factory()
            ->for($this->organization)
            ->create([
                'events' => ['user.created'],
                'is_active' => false,
            ]);

        $this->dispatcher->handleUserCreated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class, 1);
    }

    public function test_only_dispatches_to_webhooks_subscribed_to_event(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.created']]);

        Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.updated']]);

        $this->dispatcher->handleUserCreated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class, 1);
    }

    public function test_handles_wildcard_event_subscription(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['*']]);

        $this->dispatcher->handleUserCreated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class, 1);
    }

    public function test_handles_pattern_event_subscription(): void
    {
        Queue::fake();

        $user = User::factory()->for($this->organization)->create();

        Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.*']]);

        $this->dispatcher->handleUserCreated($user);
        $this->dispatcher->handleUserUpdated($user);

        Queue::assertPushed(\App\Jobs\DeliverWebhookJob::class, 2);
    }

    public function test_generates_unique_event_ids(): void
    {
        $user = User::factory()->for($this->organization)->create();

        $payload1 = $this->dispatcher->buildUserPayload($user);
        $payload2 = $this->dispatcher->buildUserPayload($user);

        $this->assertNotEquals($payload1['id'], $payload2['id']);
    }
}
