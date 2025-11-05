<?php

namespace Tests\Integration\Webhooks;

use App\Enums\WebhookDeliveryStatus;
use App\Events\OrganizationUpdatedEvent;
use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Jobs\DeliverWebhookJob;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Webhook Event Dispatch System
 *
 * Tests the complete event-driven webhook dispatch flow from event firing
 * through listener processing to job dispatch. This verifies the integration
 * between Laravel events, the WebhookEventSubscriber listener, and the
 * webhook delivery job queue.
 *
 * Key behaviors tested:
 * - Event firing triggers WebhookEventSubscriber listener
 * - Listener dispatches DeliverWebhookJob for matching webhooks
 * - MD5 deduplication prevents duplicate webhook deliveries
 * - Wildcard subscription (*) receives all events
 * - Pattern subscription (user.*, organization.*) receives matching events
 * - Exact match subscription receives only specific events
 * - Organization scoping ensures webhooks only receive own events
 * - WebhookDelivery records created for each triggered webhook
 * - Multiple webhooks triggered by single event
 * - Non-matching events don't trigger webhooks
 *
 * Event Pattern Matching:
 * - Wildcard: "*" matches ALL events
 * - Pattern: "user.*" matches user.created, user.updated, user.deleted, etc.
 * - Pattern: "organization.*" matches organization.created, organization.updated, etc.
 * - Exact: "user.created" matches ONLY user.created
 *
 * Architecture:
 * 1. Laravel Event System → Event fired (UserCreatedEvent, etc.)
 * 2. WebhookEventSubscriber → Listener processes event
 * 3. WebhookDelivery → Record created with PENDING status
 * 4. DeliverWebhookJob → Job dispatched to queue
 * 5. WebhookDeliveryService → Executes HTTP delivery
 *
 * @see App\Listeners\WebhookEventSubscriber Main event listener
 * @see App\Jobs\DeliverWebhookJob Webhook delivery job
 * @see App\Services\WebhookDeliveryService Delivery execution service
 * @see App\Models\Webhook Webhook model with event patterns
 * @see WebhookDeliveryFlowTest For HTTP delivery testing
 * @see WebhookRetryFlowTest For retry logic testing
 */
#[Group('webhooks')]
#[Group('integration')]
class WebhookEventDispatchTest extends IntegrationTestCase
{
    protected Organization $organization;

    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        // Create test organization and user
        $this->organization = $this->createOrganization(['name' => 'Event Dispatch Test Org']);
        $this->user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'testuser@example.com',
            'name' => 'Test User',
        ]);

        // Clear the static processed events cache between tests
        $this->clearWebhookEventCache();

        // Don't fake events - we want to test real event dispatching
        // Queue::fake() will prevent actual job execution but allow assertions
    }

    /**
     * Clear the static processed events cache in WebhookEventSubscriber
     */
    protected function clearWebhookEventCache(): void
    {
        // Use reflection to access the private static property
        $reflection = new \ReflectionClass(\App\Listeners\WebhookEventSubscriber::class);
        $property = $reflection->getProperty('processedEvents');
        $property->setAccessible(true);
        $property->setValue(null, []);
    }

    // ============================================================
    // COMPLETE EVENT-DRIVEN FLOW
    // ============================================================

    #[Test]
    public function event_fired_triggers_listener_and_dispatches_job()
    {
        // ARRANGE: Create webhook subscribed to user.created
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook',
            'secret' => 'test-secret',
            'is_active' => true,
            'events' => ['user.created'],
        ]);

        Queue::fake();

        // ACT: Fire UserCreatedEvent
        event(new UserCreatedEvent($this->user));

        // ASSERT: WebhookDelivery record created
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
            'status' => 'pending',
        ]);

        // ASSERT: DeliverWebhookJob dispatched
        Queue::assertPushed(DeliverWebhookJob::class, function ($job) use ($webhook) {
            return $job->delivery->webhook_id === $webhook->id &&
                   $job->delivery->event_type === 'user.created';
        });

        // ASSERT: Payload structure includes event data
        $delivery = WebhookDelivery::where('webhook_id', $webhook->id)->first();
        $this->assertNotNull($delivery);
        $this->assertEquals('user.created', $delivery->payload['event']);
        $this->assertEquals($this->user->id, $delivery->payload['data']['id']);
        $this->assertEquals($this->user->email, $delivery->payload['data']['email']);
        $this->assertArrayHasKey('timestamp', $delivery->payload);
    }

    // ============================================================
    // DUPLICATE PREVENTION (MD5 DEDUPLICATION)
    // ============================================================

    #[Test]
    public function duplicate_prevention_blocks_same_event_in_single_request()
    {
        // ARRANGE: Create webhook subscribed to user.updated
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook',
            'secret' => 'test-secret',
            'is_active' => true,
            'events' => ['user.updated'],
        ]);

        Queue::fake();

        // ACT: Fire UserUpdatedEvent twice with identical payload
        event(new UserUpdatedEvent($this->user));
        event(new UserUpdatedEvent($this->user));

        // ASSERT: Only ONE WebhookDelivery created (deduplication works)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)
            ->where('event_type', 'user.updated')
            ->count();

        $this->assertEquals(1, $deliveryCount, 'Duplicate event should be prevented by MD5 deduplication');

        // ASSERT: Only ONE DeliverWebhookJob dispatched
        Queue::assertPushed(DeliverWebhookJob::class, 1);
    }

    // ============================================================
    // WILDCARD SUBSCRIPTION MATCHING
    // ============================================================

    #[Test]
    public function wildcard_subscription_receives_all_events()
    {
        // ARRANGE: Create webhook with wildcard subscription (*)
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-wildcard',
            'secret' => 'wildcard-secret',
            'is_active' => true,
            'events' => ['*'],
        ]);

        Queue::fake();

        // ACT: Fire multiple different events
        event(new UserCreatedEvent($this->user));
        event(new UserUpdatedEvent($this->user));
        event(new UserDeletedEvent($this->user));
        event(new OrganizationUpdatedEvent($this->organization));

        // ASSERT: Webhook received ALL four events
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(4, $deliveryCount, 'Wildcard subscription should receive all events');

        // ASSERT: Four separate jobs dispatched
        Queue::assertPushed(DeliverWebhookJob::class, 4);

        // ASSERT: Each event type recorded
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.deleted',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);
    }

    // ============================================================
    // PATTERN SUBSCRIPTION MATCHING (user.*)
    // ============================================================

    #[Test]
    public function pattern_subscription_user_asterisk_receives_user_events()
    {
        // ARRANGE: Create webhook subscribed to user.* pattern
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-user-pattern',
            'secret' => 'user-pattern-secret',
            'is_active' => true,
            'events' => ['user.*'],
        ]);

        Queue::fake();

        // ACT: Fire user events and organization event
        event(new UserCreatedEvent($this->user));
        event(new UserUpdatedEvent($this->user));
        event(new UserDeletedEvent($this->user));
        event(new OrganizationUpdatedEvent($this->organization));

        // ASSERT: Webhook received only user.* events (3 events)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(3, $deliveryCount, 'user.* pattern should match only user events');

        // ASSERT: Three jobs dispatched
        Queue::assertPushed(DeliverWebhookJob::class, 3);

        // ASSERT: User events recorded
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.deleted',
        ]);

        // ASSERT: Organization event NOT recorded
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);
    }

    // ============================================================
    // PATTERN SUBSCRIPTION MATCHING (organization.*)
    // ============================================================

    #[Test]
    public function pattern_subscription_organization_asterisk_receives_organization_events()
    {
        // ARRANGE: Create webhook subscribed to organization.* pattern
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-org-pattern',
            'secret' => 'org-pattern-secret',
            'is_active' => true,
            'events' => ['organization.*'],
        ]);

        Queue::fake();

        // ACT: Fire organization event and user events
        event(new OrganizationUpdatedEvent($this->organization));
        event(new UserCreatedEvent($this->user));
        event(new UserUpdatedEvent($this->user));

        // ASSERT: Webhook received only organization.* events (1 event)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'organization.* pattern should match only organization events');

        // ASSERT: One job dispatched
        Queue::assertPushed(DeliverWebhookJob::class, 1);

        // ASSERT: Organization event recorded
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);

        // ASSERT: User events NOT recorded
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);
    }

    // ============================================================
    // EXACT MATCH SUBSCRIPTION
    // ============================================================

    #[Test]
    public function exact_match_subscription_receives_only_specific_event()
    {
        // ARRANGE: Create webhook subscribed to ONLY user.created (exact match)
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-exact',
            'secret' => 'exact-secret',
            'is_active' => true,
            'events' => ['user.created'],
        ]);

        Queue::fake();

        // ACT: Fire multiple user events
        event(new UserCreatedEvent($this->user));
        event(new UserUpdatedEvent($this->user));
        event(new UserDeletedEvent($this->user));

        // ASSERT: Webhook received ONLY user.created (1 event)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'Exact match should receive only user.created');

        // ASSERT: One job dispatched
        Queue::assertPushed(DeliverWebhookJob::class, 1);

        // ASSERT: Only user.created recorded
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);

        // ASSERT: Other user events NOT recorded
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.deleted',
        ]);
    }

    // ============================================================
    // ORGANIZATION-SCOPED FILTERING
    // ============================================================

    #[Test]
    public function organization_scoping_filters_events_correctly()
    {
        // ARRANGE: Create two organizations with separate webhooks
        $organizationA = $this->organization;
        $organizationB = $this->createOrganization(['name' => 'Organization B']);

        $webhookA = Webhook::factory()->create([
            'organization_id' => $organizationA->id,
            'url' => 'https://example.com/webhook-a',
            'secret' => 'secret-a',
            'is_active' => true,
            'events' => ['user.created'],
        ]);

        $webhookB = Webhook::factory()->create([
            'organization_id' => $organizationB->id,
            'url' => 'https://example.com/webhook-b',
            'secret' => 'secret-b',
            'is_active' => true,
            'events' => ['user.created'],
        ]);

        Queue::fake();

        // ACT: Fire UserCreatedEvent for user in Organization A
        event(new UserCreatedEvent($this->user)); // This user belongs to Organization A

        // ASSERT: Only webhook A received the event (organization boundary respected)
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhookA->id,
            'event_type' => 'user.created',
        ]);

        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhookB->id,
            'event_type' => 'user.created',
        ]);

        // ASSERT: Only one job dispatched (for webhook A)
        Queue::assertPushed(DeliverWebhookJob::class, 1);

        Queue::assertPushed(DeliverWebhookJob::class, function ($job) use ($webhookA) {
            return $job->delivery->webhook_id === $webhookA->id;
        });
    }

    // ============================================================
    // WEBHOOK DELIVERY RECORD CREATION
    // ============================================================

    #[Test]
    public function webhook_delivery_record_created_with_correct_structure()
    {
        // ARRANGE: Create webhook
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook',
            'secret' => 'test-secret',
            'is_active' => true,
            'events' => ['user.updated'],
        ]);

        Queue::fake();

        // ACT: Fire UserUpdatedEvent
        event(new UserUpdatedEvent($this->user));

        // ASSERT: WebhookDelivery record exists with correct fields
        $delivery = WebhookDelivery::where('webhook_id', $webhook->id)->first();

        $this->assertNotNull($delivery, 'WebhookDelivery record should be created');
        $this->assertEquals($webhook->id, $delivery->webhook_id);
        $this->assertEquals('user.updated', $delivery->event_type);
        $this->assertEquals(WebhookDeliveryStatus::PENDING, $delivery->status);
        $this->assertIsArray($delivery->payload);
        $this->assertNotNull($delivery->created_at);

        // ASSERT: Payload has correct structure
        $payload = $delivery->payload;
        $this->assertEquals('user.updated', $payload['event']);
        $this->assertArrayHasKey('data', $payload);
        $this->assertArrayHasKey('timestamp', $payload);
        $this->assertArrayHasKey('organization_id', $payload);

        // ASSERT: Event ID generated
        $this->assertArrayHasKey('id', $payload);
        $this->assertStringStartsWith('evt_', $payload['id']);
    }

    // ============================================================
    // MULTIPLE WEBHOOKS TRIGGERED
    // ============================================================

    #[Test]
    public function multiple_webhooks_triggered_by_single_event()
    {
        // ARRANGE: Create three webhooks subscribed to same event
        $webhook1 = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-1',
            'secret' => 'secret-1',
            'is_active' => true,
            'events' => ['user.created'],
        ]);

        $webhook2 = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-2',
            'secret' => 'secret-2',
            'is_active' => true,
            'events' => ['user.*'],
        ]);

        $webhook3 = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-3',
            'secret' => 'secret-3',
            'is_active' => true,
            'events' => ['*'],
        ]);

        Queue::fake();

        // ACT: Fire single UserCreatedEvent
        event(new UserCreatedEvent($this->user));

        // ASSERT: All three webhooks triggered
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook1->id,
            'event_type' => 'user.created',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook2->id,
            'event_type' => 'user.created',
        ]);
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook3->id,
            'event_type' => 'user.created',
        ]);

        // ASSERT: Three jobs dispatched
        Queue::assertPushed(DeliverWebhookJob::class, 3);

        // ASSERT: Each job for different webhook
        Queue::assertPushed(DeliverWebhookJob::class, function ($job) use ($webhook1) {
            return $job->delivery->webhook_id === $webhook1->id;
        });
        Queue::assertPushed(DeliverWebhookJob::class, function ($job) use ($webhook2) {
            return $job->delivery->webhook_id === $webhook2->id;
        });
        Queue::assertPushed(DeliverWebhookJob::class, function ($job) use ($webhook3) {
            return $job->delivery->webhook_id === $webhook3->id;
        });
    }

    // ============================================================
    // NON-MATCHING EVENTS DON'T TRIGGER WEBHOOKS
    // ============================================================

    #[Test]
    public function non_matching_events_do_not_trigger_webhooks()
    {
        // ARRANGE: Create webhook subscribed ONLY to organization.updated
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook',
            'secret' => 'test-secret',
            'is_active' => true,
            'events' => ['organization.updated'],
        ]);

        Queue::fake();

        // ACT: Fire user events (NOT organization events)
        event(new UserCreatedEvent($this->user));
        event(new UserUpdatedEvent($this->user));
        event(new UserDeletedEvent($this->user));

        // ASSERT: NO webhook deliveries created
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(0, $deliveryCount, 'Non-matching events should not trigger webhook');

        // ASSERT: NO jobs dispatched
        Queue::assertNotPushed(DeliverWebhookJob::class);

        // ASSERT: Database has no deliveries for this webhook
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
        ]);
    }

    // ============================================================
    // INACTIVE WEBHOOKS NOT TRIGGERED
    // ============================================================

    #[Test]
    public function inactive_webhooks_not_triggered_by_events()
    {
        // ARRANGE: Create INACTIVE webhook
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-inactive',
            'secret' => 'inactive-secret',
            'is_active' => false, // Webhook disabled
            'events' => ['user.created'],
        ]);

        Queue::fake();

        // ACT: Fire UserCreatedEvent
        event(new UserCreatedEvent($this->user));

        // ASSERT: NO webhook delivery created (webhook inactive)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(0, $deliveryCount, 'Inactive webhooks should not be triggered');

        // ASSERT: NO jobs dispatched
        Queue::assertNotPushed(DeliverWebhookJob::class);

        // ASSERT: Database has no deliveries for inactive webhook
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
        ]);
    }
}
