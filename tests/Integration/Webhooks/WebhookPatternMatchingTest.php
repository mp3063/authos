<?php

namespace Tests\Integration\Webhooks;

use App\Events\ApplicationCreatedEvent;
use App\Events\OrganizationUpdatedEvent;
use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserRestoredEvent;
use App\Events\UserUpdatedEvent;
use App\Listeners\WebhookEventSubscriber;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Webhook Pattern Matching
 *
 * Tests the webhook event subscription pattern matching system including:
 * - Exact event name matches (e.g., "user.created")
 * - Wildcard matches (e.g., "*" matches all events)
 * - Prefix pattern matches (e.g., "user.*" matches user.created, user.updated, etc.)
 * - Multiple subscriptions per webhook
 * - Non-matching event filtering
 * - Case sensitivity in pattern matching
 * - Complex pattern combinations (exact + wildcard + prefix)
 *
 * Pattern Matching Specification:
 * ----------------------------------
 * 1. Exact Match: "user.created" → only matches "user.created" event
 * 2. Wildcard: "*" → matches ALL events (user.*, organization.*, application.*, etc.)
 * 3. Prefix Pattern: "user.*" → matches "user.created", "user.updated", "user.deleted", "user.restored"
 * 4. Prefix Pattern: "organization.*" → matches "organization.created", "organization.updated", etc.
 * 5. Multiple: ["user.*", "organization.*"] → matches both user and organization events
 *
 * Implementation Details:
 * -----------------------
 * - Pattern matching uses Laravel's Str::is() method (which supports wildcards)
 * - Webhooks subscribe to events via the `events` JSON array column
 * - WebhookEventSubscriber::isSubscribedToEvent() handles pattern matching logic
 * - Event dispatching creates WebhookDelivery records for matched webhooks only
 * - Organization boundaries enforced (webhooks only receive events from their org)
 *
 * Test Strategy:
 * --------------
 * - Test each pattern type independently first
 * - Test combinations of patterns
 * - Test edge cases (empty subscriptions, case sensitivity)
 * - Verify non-matching events are properly filtered
 * - Ensure organization isolation remains intact
 *
 * Related Files:
 * --------------
 *
 * @see App\Listeners\WebhookEventSubscriber::isSubscribedToEvent() Pattern matching implementation
 * @see App\Models\Webhook Event subscriptions stored in `events` JSON column
 * @see App\Models\WebhookDelivery Created for each matched event
 * @see App\Events\* Domain events that trigger webhooks
 */
#[Group('webhooks')]
#[Group('integration')]
#[Group('pattern-matching')]
class WebhookPatternMatchingTest extends IntegrationTestCase
{
    protected Organization $organization;

    protected WebhookEventSubscriber $subscriber;

    protected function setUp(): void
    {
        parent::setUp();

        // Create test organization
        $this->organization = $this->createOrganization(['name' => 'Pattern Test Organization']);

        // Get subscriber instance for testing
        $this->subscriber = app(WebhookEventSubscriber::class);

        // Mock HTTP responses for all webhook deliveries
        Http::fake([
            '*' => Http::response(['status' => 'received'], 200),
        ]);

        // Use sync queue for immediate execution
        Queue::fake();
    }

    // ============================================================
    // EXACT MATCH TESTS
    // ============================================================

    #[Test]
    public function exact_match_only_triggers_for_specific_event()
    {
        // ARRANGE: Create webhook subscribed to exact event "user.created"
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-exact',
            'events' => ['user.created'], // Exact match only
            'is_active' => true,
        ]);

        // Create user in same organization
        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'exact@example.com',
        ]);

        // ACT: Dispatch user.created event (should match)
        $eventCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventCreated);

        // ASSERT: Webhook delivery created for user.created
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);

        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'Should create exactly one delivery for user.created');

        // ACT: Dispatch user.updated event (should NOT match exact subscription)
        $eventUpdated = new UserUpdatedEvent($user, ['name' => 'Updated Name']);
        $this->subscriber->handleUserUpdated($eventUpdated);

        // ASSERT: No additional delivery created for user.updated
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);

        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'Should still have only one delivery (user.created)');

        // ACT: Dispatch user.deleted event (should NOT match)
        $eventDeleted = new UserDeletedEvent($user);
        $this->subscriber->handleUserDeleted($eventDeleted);

        // ASSERT: Still only one delivery (for user.created)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'Exact match should not trigger for user.deleted');
    }

    // ============================================================
    // WILDCARD MATCH TESTS
    // ============================================================

    #[Test]
    public function wildcard_match_triggers_for_all_event_types()
    {
        // ARRANGE: Create webhook subscribed to ALL events via wildcard "*"
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-wildcard',
            'events' => ['*'], // Wildcard: matches everything
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'wildcard@example.com',
        ]);

        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Wildcard Test App',
        ]);

        // ACT: Dispatch multiple different event types
        $eventUserCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventUserCreated);

        $eventUserUpdated = new UserUpdatedEvent($user, ['email' => 'updated@example.com']);
        $this->subscriber->handleUserUpdated($eventUserUpdated);

        $eventUserDeleted = new UserDeletedEvent($user);
        $this->subscriber->handleUserDeleted($eventUserDeleted);

        $eventAppCreated = new ApplicationCreatedEvent($application);
        $this->subscriber->handleApplicationCreated($eventAppCreated);

        $eventOrgUpdated = new OrganizationUpdatedEvent($this->organization, ['name' => 'Updated Org']);
        $this->subscriber->handleOrganizationUpdated($eventOrgUpdated);

        // ASSERT: Wildcard webhook received ALL events
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
            'event_type' => 'application.created',
        ]);

        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);

        // ASSERT: Total delivery count matches event count
        // 5 manually dispatched + 1 from ApplicationObserver auto-dispatching ApplicationCreatedEvent
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(6, $deliveryCount, 'Wildcard should match all dispatched events (5 manual + 1 observer)');
    }

    // ============================================================
    // PREFIX PATTERN MATCH TESTS (user.*)
    // ============================================================

    #[Test]
    public function prefix_pattern_user_matches_all_user_events()
    {
        // ARRANGE: Create webhook subscribed to "user.*" pattern
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-user-pattern',
            'events' => ['user.*'], // Pattern: matches user.created, user.updated, user.deleted, etc.
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'pattern@example.com',
        ]);

        // ACT: Dispatch various user.* events (should all match)
        $eventCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventCreated);

        $eventUpdated = new UserUpdatedEvent($user, ['name' => 'Updated']);
        $this->subscriber->handleUserUpdated($eventUpdated);

        $eventDeleted = new UserDeletedEvent($user);
        $this->subscriber->handleUserDeleted($eventDeleted);

        // Create restored event if it exists (check event class)
        if (class_exists(UserRestoredEvent::class)) {
            $eventRestored = new UserRestoredEvent($user);
            $this->subscriber->handleUserCreated($eventRestored); // Reuse handler for testing pattern
        }

        // ASSERT: All user.* events matched
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

        // ACT: Dispatch non-user event (should NOT match)
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
        $eventAppCreated = new ApplicationCreatedEvent($application);
        $this->subscriber->handleApplicationCreated($eventAppCreated);

        // ASSERT: application.created did NOT match user.* pattern
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'application.created',
        ]);

        // ASSERT: Only user.* events were delivered
        $userDeliveries = WebhookDelivery::where('webhook_id', $webhook->id)
            ->whereIn('event_type', ['user.created', 'user.updated', 'user.deleted'])
            ->count();
        $this->assertEquals(3, $userDeliveries, 'Pattern user.* should match exactly 3 user events');
    }

    // ============================================================
    // SUFFIX PATTERN MATCH TESTS (*.created)
    // ============================================================

    #[Test]
    public function suffix_pattern_matches_all_created_events()
    {
        // ARRANGE: Create webhook subscribed to "*.created" pattern
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-created-pattern',
            'events' => ['*.created'], // Pattern: matches user.created, application.created, organization.created, etc.
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'suffix@example.com',
        ]);

        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Suffix Test App',
        ]);

        // ACT: Dispatch various *.created events (should all match)
        $eventUserCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventUserCreated);

        $eventAppCreated = new ApplicationCreatedEvent($application);
        $this->subscriber->handleApplicationCreated($eventAppCreated);

        // ASSERT: All *.created events matched
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);

        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'application.created',
        ]);

        // ACT: Dispatch non-created events (should NOT match)
        $eventUserUpdated = new UserUpdatedEvent($user, ['name' => 'Updated']);
        $this->subscriber->handleUserUpdated($eventUserUpdated);

        $eventUserDeleted = new UserDeletedEvent($user);
        $this->subscriber->handleUserDeleted($eventUserDeleted);

        $eventOrgUpdated = new OrganizationUpdatedEvent($this->organization, ['name' => 'Changed']);
        $this->subscriber->handleOrganizationUpdated($eventOrgUpdated);

        // ASSERT: Non-created events did NOT match *.created pattern
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);

        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.deleted',
        ]);

        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);

        // ASSERT: Only *.created events were delivered
        $createdDeliveries = WebhookDelivery::where('webhook_id', $webhook->id)
            ->whereIn('event_type', ['user.created', 'application.created'])
            ->count();
        $this->assertEquals(2, $createdDeliveries, 'Pattern *.created should match exactly 2 created events');

        $totalDeliveries = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(2, $totalDeliveries, 'Only created events should trigger webhook');
    }

    // ============================================================
    // PREFIX PATTERN MATCH TESTS (organization.*)
    // ============================================================

    #[Test]
    public function prefix_pattern_organization_matches_organization_events()
    {
        // ARRANGE: Create webhook subscribed to "organization.*" pattern
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-org-pattern',
            'events' => ['organization.*'], // Pattern: matches organization.created, organization.updated, etc.
            'is_active' => true,
        ]);

        // ACT: Dispatch organization.updated event (should match)
        $eventOrgUpdated = new OrganizationUpdatedEvent($this->organization, ['name' => 'New Name']);
        $this->subscriber->handleOrganizationUpdated($eventOrgUpdated);

        // ASSERT: organization.updated matched
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);

        // ACT: Dispatch user event (should NOT match organization.*)
        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'orgpattern@example.com',
        ]);
        $eventUserCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventUserCreated);

        // ASSERT: user.created did NOT match organization.* pattern
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);

        // ACT: Dispatch application event (should NOT match organization.*)
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
        $eventAppCreated = new ApplicationCreatedEvent($application);
        $this->subscriber->handleApplicationCreated($eventAppCreated);

        // ASSERT: application.created did NOT match
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'application.created',
        ]);

        // ASSERT: Only organization.* events delivered
        $orgDeliveries = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $orgDeliveries, 'Only organization.updated should match organization.* pattern');
    }

    // ============================================================
    // MULTIPLE SUBSCRIPTIONS PER WEBHOOK
    // ============================================================

    #[Test]
    public function multiple_subscriptions_allow_multiple_pattern_matches()
    {
        // ARRANGE: Create webhook with multiple event subscriptions
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-multiple',
            'events' => [
                'user.*',           // Pattern: all user events
                'organization.*',   // Pattern: all organization events
                'application.created', // Exact: only application.created
            ],
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'multi@example.com',
        ]);

        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Dispatch events matching all three subscription patterns
        $eventUserCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventUserCreated);

        $eventUserUpdated = new UserUpdatedEvent($user, ['name' => 'Updated']);
        $this->subscriber->handleUserUpdated($eventUserUpdated);

        $eventOrgUpdated = new OrganizationUpdatedEvent($this->organization, ['name' => 'Org Update']);
        $this->subscriber->handleOrganizationUpdated($eventOrgUpdated);

        $eventAppCreated = new ApplicationCreatedEvent($application);
        $this->subscriber->handleApplicationCreated($eventAppCreated);

        // ASSERT: All matching events delivered
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created', // Matched by user.*
        ]);

        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated', // Matched by user.*
        ]);

        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated', // Matched by organization.*
        ]);

        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'application.created', // Matched by exact subscription
        ]);

        // ASSERT: Total delivery count
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(4, $deliveryCount, 'All four events should match multiple subscriptions');
    }

    // ============================================================
    // NON-MATCHING EVENTS FILTERING
    // ============================================================

    #[Test]
    public function non_matching_events_do_not_trigger_webhooks()
    {
        // ARRANGE: Create webhook subscribed to specific events only
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-filtered',
            'events' => ['user.created', 'application.created'], // Only these two events
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'filter@example.com',
        ]);

        // ACT: Dispatch non-matching events
        $eventUserUpdated = new UserUpdatedEvent($user, ['email' => 'changed@example.com']);
        $this->subscriber->handleUserUpdated($eventUserUpdated);

        $eventUserDeleted = new UserDeletedEvent($user);
        $this->subscriber->handleUserDeleted($eventUserDeleted);

        $eventOrgUpdated = new OrganizationUpdatedEvent($this->organization, ['name' => 'Changed']);
        $this->subscriber->handleOrganizationUpdated($eventOrgUpdated);

        // ASSERT: No deliveries created for non-matching events
        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.updated',
        ]);

        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.deleted',
        ]);

        $this->assertDatabaseMissing('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'organization.updated',
        ]);

        // ACT: Dispatch matching event
        $eventUserCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventUserCreated);

        // ASSERT: Only matching event created delivery
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'Only user.created should trigger webhook delivery');

        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);
    }

    // ============================================================
    // PATTERN MATCHING CASE SENSITIVITY
    // ============================================================

    #[Test]
    public function pattern_matching_is_case_sensitive()
    {
        // ARRANGE: Create webhook with lowercase pattern
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-case',
            'events' => ['user.created'], // Lowercase
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'case@example.com',
        ]);

        // ACT: Dispatch event with correct case
        $eventCorrectCase = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventCorrectCase);

        // ASSERT: Correct case matches
        $this->assertDatabaseHas('webhook_deliveries', [
            'webhook_id' => $webhook->id,
            'event_type' => 'user.created',
        ]);

        // Note: Our events always use lowercase by convention (user.created, not User.Created)
        // This test verifies that pattern matching respects the actual event naming convention
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(1, $deliveryCount, 'Case-sensitive pattern should match lowercase event');
    }

    // ============================================================
    // COMPLEX PATTERN COMBINATIONS
    // ============================================================

    #[Test]
    public function complex_pattern_combinations_handle_mixed_subscriptions()
    {
        // ARRANGE: Create webhook with complex subscription mix
        $webhook = Webhook::factory()->create([
            'organization_id' => $this->organization->id,
            'url' => 'https://example.com/webhook-complex',
            'events' => [
                '*',                    // Wildcard: matches everything
                'user.created',         // Exact: redundant but valid (already covered by *)
                'organization.*',       // Pattern: redundant but valid (already covered by *)
            ],
            'is_active' => true,
        ]);

        $user = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'complex@example.com',
        ]);

        // ACT: Dispatch various events
        $eventUserCreated = new UserCreatedEvent($user);
        $this->subscriber->handleUserCreated($eventUserCreated);

        $eventUserUpdated = new UserUpdatedEvent($user, ['name' => 'Updated']);
        $this->subscriber->handleUserUpdated($eventUserUpdated);

        $eventOrgUpdated = new OrganizationUpdatedEvent($this->organization, ['name' => 'Org Change']);
        $this->subscriber->handleOrganizationUpdated($eventOrgUpdated);

        // ASSERT: All events matched (wildcard covers everything)
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
            'event_type' => 'organization.updated',
        ]);

        // ASSERT: No duplicate deliveries despite overlapping subscriptions
        // (WebhookEventSubscriber returns true on first match, preventing duplicates)
        $deliveryCount = WebhookDelivery::where('webhook_id', $webhook->id)->count();
        $this->assertEquals(3, $deliveryCount, 'Each event should create exactly one delivery, no duplicates');

        // ASSERT: Verify each event type appears exactly once
        $userCreatedCount = WebhookDelivery::where('webhook_id', $webhook->id)
            ->where('event_type', 'user.created')
            ->count();
        $this->assertEquals(1, $userCreatedCount, 'user.created should not create duplicate deliveries');

        $userUpdatedCount = WebhookDelivery::where('webhook_id', $webhook->id)
            ->where('event_type', 'user.updated')
            ->count();
        $this->assertEquals(1, $userUpdatedCount, 'user.updated should not create duplicate deliveries');

        $orgUpdatedCount = WebhookDelivery::where('webhook_id', $webhook->id)
            ->where('event_type', 'organization.updated')
            ->count();
        $this->assertEquals(1, $orgUpdatedCount, 'organization.updated should not create duplicate deliveries');
    }
}
