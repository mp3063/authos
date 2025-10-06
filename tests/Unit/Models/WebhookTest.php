<?php

namespace Tests\Unit\Models;

use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Tests\TestCase;

class WebhookTest extends TestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    public function test_encrypts_secret_on_save(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['secret' => 'plain_secret_123']);

        // Verify secret is encrypted in database
        $raw = \DB::table('webhooks')->where('id', $webhook->id)->first();
        $this->assertNotEquals('plain_secret_123', $raw->secret);
    }

    public function test_decrypts_secret_on_retrieval(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['secret' => 'plain_secret_123']);

        $webhook->refresh();

        $this->assertEquals('plain_secret_123', $webhook->secret);
    }

    public function test_tracks_consecutive_failures(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['consecutive_failures' => 0]);

        $webhook->incrementFailures();

        $this->assertEquals(1, $webhook->consecutive_failures);
    }

    public function test_resets_consecutive_failures_on_success(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['consecutive_failures' => 5]);

        $webhook->resetFailures();

        $this->assertEquals(0, $webhook->consecutive_failures);
    }

    public function test_calculates_average_response_time(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'delivery_stats' => [
                    'total_deliveries' => 10,
                    'successful_deliveries' => 8,
                    'failed_deliveries' => 2,
                    'average_response_time_ms' => 150,
                ],
            ]);

        $this->assertEquals(150, $webhook->averageResponseTime());
    }

    public function test_has_deliveries_relationship(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create();

        WebhookDelivery::factory()
            ->for($webhook)
            ->count(3)
            ->create();

        $this->assertCount(3, $webhook->deliveries);
    }

    public function test_belongs_to_organization(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create();

        $this->assertInstanceOf(Organization::class, $webhook->organization);
        $this->assertEquals($this->organization->id, $webhook->organization->id);
    }

    public function test_scope_active(): void
    {
        Webhook::factory()
            ->for($this->organization)
            ->count(2)
            ->create(['is_active' => true]);

        Webhook::factory()
            ->for($this->organization)
            ->create(['is_active' => false]);

        $activeWebhooks = Webhook::active()->get();

        $this->assertCount(2, $activeWebhooks);
    }

    public function test_scope_for_event(): void
    {
        Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.created', 'user.updated']]);

        Webhook::factory()
            ->for($this->organization)
            ->create(['events' => ['user.deleted']]);

        $webhooks = Webhook::forEvent('user.created')->get();

        $this->assertCount(1, $webhooks);
    }

    public function test_is_disabled_when_max_failures_reached(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'consecutive_failures' => 10,
                'is_active' => false,
                'disabled_at' => now(),
            ]);

        $this->assertFalse($webhook->is_active);
        $this->assertNotNull($webhook->disabled_at);
    }

    public function test_can_be_re_enabled(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'is_active' => false,
                'disabled_at' => now(),
                'consecutive_failures' => 10,
            ]);

        $webhook->enable();

        $this->assertTrue($webhook->is_active);
        $this->assertNull($webhook->disabled_at);
        $this->assertEquals(0, $webhook->consecutive_failures);
    }

    public function test_stores_events_as_json(): void
    {
        $events = ['user.created', 'user.updated', 'user.deleted'];

        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['events' => $events]);

        $webhook->refresh();

        $this->assertEquals($events, $webhook->events);
        $this->assertIsArray($webhook->events);
    }

    public function test_stores_delivery_stats_as_json(): void
    {
        $stats = [
            'total_deliveries' => 100,
            'successful_deliveries' => 95,
            'failed_deliveries' => 5,
            'average_response_time_ms' => 120,
        ];

        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['delivery_stats' => $stats]);

        $webhook->refresh();

        $this->assertEquals($stats, $webhook->delivery_stats);
        $this->assertIsArray($webhook->delivery_stats);
    }

    public function test_updates_delivery_stats(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'delivery_stats' => [
                    'total_deliveries' => 10,
                    'successful_deliveries' => 8,
                    'failed_deliveries' => 2,
                    'average_response_time_ms' => 100,
                ],
            ]);

        $webhook->updateDeliveryStats(true, 150);

        $stats = $webhook->delivery_stats;

        $this->assertEquals(11, $stats['total_deliveries']);
        $this->assertEquals(9, $stats['successful_deliveries']);
        $this->assertEquals(2, $stats['failed_deliveries']);
    }

    public function test_last_delivered_at_is_updated(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['last_delivered_at' => null]);

        $now = now();
        $webhook->update(['last_delivered_at' => $now]);

        $this->assertNotNull($webhook->last_delivered_at);
        $this->assertEquals($now->timestamp, $webhook->last_delivered_at->timestamp);
    }
}
