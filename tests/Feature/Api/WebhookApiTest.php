<?php

namespace Tests\Feature\Api;

use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Database\Seeders\WebhookEventSeeder;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\Passport;
use Tests\TestCase;

class WebhookApiTest extends TestCase
{
    private User $user;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        // Seed webhook events for validation
        $this->seed(WebhookEventSeeder::class);

        $this->organization = Organization::factory()->create();
        $this->user = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->user, ['webhooks.manage']);
    }

    public function test_can_list_webhooks(): void
    {
        Webhook::factory()
            ->count(3)
            ->for($this->organization)
            ->create();

        $response = $this->getJson('/api/v1/webhooks');

        $response->assertOk()
            ->assertJsonCount(3, 'data')
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'url',
                        'events',
                        'is_active',
                        'description',
                        'created_at',
                        'updated_at',
                    ],
                ],
            ]);
    }

    public function test_cannot_see_other_organizations_webhooks(): void
    {
        $otherOrg = Organization::factory()->create();
        Webhook::factory()->for($otherOrg)->count(2)->create();

        Webhook::factory()->for($this->organization)->create();

        $response = $this->getJson('/api/v1/webhooks');

        $response->assertOk()
            ->assertJsonCount(1, 'data');
    }

    public function test_can_create_webhook(): void
    {
        $data = [
            'name' => 'Test Webhook',
            'url' => 'https://example.com/webhook',
            'events' => ['user.created', 'user.updated'],
            'description' => 'Test webhook',
        ];

        $response = $this->postJson('/api/v1/webhooks', $data);

        $response->assertCreated()
            ->assertJsonStructure([
                'success',
                'data' => [
                    'id',
                    'url',
                    'events',
                    'secret',
                    'is_active',
                ],
            ]);

        $this->assertDatabaseHas('webhooks', [
            'url' => 'https://example.com/webhook',
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_requires_https_url(): void
    {
        $data = [
            'name' => 'Test Webhook',
            'url' => 'http://example.com/webhook',
            'events' => ['user.created'],
        ];

        $response = $this->postJson('/api/v1/webhooks', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['url']);
    }

    public function test_validates_events_array(): void
    {
        $data = [
            'name' => 'Test Webhook',
            'url' => 'https://example.com/webhook',
            'events' => 'not-an-array',
        ];

        $response = $this->postJson('/api/v1/webhooks', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['events']);
    }

    public function test_can_update_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['url' => 'https://old.example.com/webhook']);

        $data = [
            'url' => 'https://new.example.com/webhook',
            'events' => ['user.created', 'user.updated', 'user.deleted'],
            'description' => 'Updated webhook',
        ];

        $response = $this->putJson("/api/v1/webhooks/{$webhook->id}", $data);

        $response->assertOk()
            ->assertJsonPath('data.url', 'https://new.example.com/webhook')
            ->assertJsonPath('data.description', 'Updated webhook');
    }

    public function test_cannot_update_other_organizations_webhook(): void
    {
        $otherOrg = Organization::factory()->create();
        $webhook = Webhook::factory()->for($otherOrg)->create();

        $response = $this->putJson("/api/v1/webhooks/{$webhook->id}", [
            'url' => 'https://example.com/webhook',
        ]);

        $response->assertNotFound();
    }

    public function test_can_delete_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create();

        $response = $this->deleteJson("/api/v1/webhooks/{$webhook->id}");

        $response->assertNoContent();

        $this->assertSoftDeleted('webhooks', ['id' => $webhook->id]);
    }

    public function test_cannot_delete_other_organizations_webhook(): void
    {
        $otherOrg = Organization::factory()->create();
        $webhook = Webhook::factory()->for($otherOrg)->create();

        $response = $this->deleteJson("/api/v1/webhooks/{$webhook->id}");

        $response->assertNotFound();
    }

    public function test_can_test_webhook(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'success'], 200),
        ]);

        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['url' => 'https://example.com/webhook']);

        $response = $this->postJson("/api/v1/webhooks/{$webhook->id}/test");

        $response->assertOk()
            ->assertJsonPath('success', true)
            ->assertJsonStructure([
                'data' => [
                    'status_code',
                    'response_time_ms',
                ],
            ]);
    }

    public function test_can_rotate_secret(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create();

        $oldSecret = $webhook->secret;

        $response = $this->postJson("/api/v1/webhooks/{$webhook->id}/rotate-secret");

        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'secret',
                ],
            ]);

        $webhook->refresh();

        $this->assertNotEquals($oldSecret, $webhook->secret);
    }

    public function test_can_enable_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'is_active' => false,
                'disabled_at' => now(),
            ]);

        $response = $this->postJson("/api/v1/webhooks/{$webhook->id}/enable");

        $response->assertOk();

        $webhook->refresh();

        $this->assertTrue($webhook->is_active);
        $this->assertNull($webhook->disabled_at);
    }

    public function test_can_disable_webhook(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['is_active' => true]);

        $response = $this->postJson("/api/v1/webhooks/{$webhook->id}/disable");

        $response->assertOk();

        $webhook->refresh();

        $this->assertFalse($webhook->is_active);
        $this->assertNotNull($webhook->disabled_at);
    }

    public function test_can_get_delivery_history(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create();

        WebhookDelivery::factory()
            ->for($webhook)
            ->count(5)
            ->create();

        $response = $this->getJson("/api/v1/webhooks/{$webhook->id}/deliveries");

        $response->assertOk()
            ->assertJsonCount(5, 'data')
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'status',
                        'response_status',
                        'response_time_ms',
                        'attempt',
                        'created_at',
                    ],
                ],
            ]);
    }

    public function test_can_get_webhook_stats(): void
    {
        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create([
                'delivery_stats' => [
                    'total_deliveries' => 100,
                    'successful_deliveries' => 95,
                    'failed_deliveries' => 5,
                    'average_response_time_ms' => 150,
                ],
            ]);

        $response = $this->getJson("/api/v1/webhooks/{$webhook->id}/stats");

        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'total_deliveries',
                    'successful_deliveries',
                    'failed_deliveries',
                    'success_rate',
                    'average_response_time_ms',
                ],
            ]);
    }

    public function test_can_retry_failed_delivery(): void
    {
        Http::fake([
            'example.com/*' => Http::response(['status' => 'success'], 200),
        ]);

        $webhook = Webhook::factory()
            ->for($this->organization)
            ->create(['url' => 'https://example.com/webhook']);

        $delivery = WebhookDelivery::factory()
            ->for($webhook)
            ->create(['status' => 'failed']);

        $response = $this->postJson("/api/v1/webhooks/deliveries/{$delivery->id}/retry");

        $response->assertOk();
    }

    public function test_can_list_webhook_events(): void
    {
        $response = $this->getJson('/api/v1/webhooks/events');

        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'name',
                        'description',
                        'category',
                    ],
                ],
            ]);
    }

    public function test_requires_authentication(): void
    {
        Passport::actingAs(User::factory()->create(), []);

        $response = $this->getJson('/api/v1/webhooks');

        $response->assertForbidden();
    }

    public function test_validates_max_webhooks_per_organization(): void
    {
        // Create max webhooks (e.g., 10)
        Webhook::factory()
            ->for($this->organization)
            ->count(10)
            ->create();

        $data = [
            'name' => 'Test Webhook',
            'url' => 'https://example.com/webhook',
            'events' => ['user.created'],
        ];

        $response = $this->postJson('/api/v1/webhooks', $data);

        $response->assertUnprocessable()
            ->assertJsonValidationErrors(['organization_id']);
    }

    public function test_filters_webhooks_by_active_status(): void
    {
        Webhook::factory()
            ->for($this->organization)
            ->count(2)
            ->create(['is_active' => true]);

        Webhook::factory()
            ->for($this->organization)
            ->create(['is_active' => false]);

        $response = $this->getJson('/api/v1/webhooks?filter[is_active]=true');

        $response->assertOk()
            ->assertJsonCount(2, 'data');
    }

    public function test_paginates_webhooks(): void
    {
        Webhook::factory()
            ->for($this->organization)
            ->count(25)
            ->create();

        $response = $this->getJson('/api/v1/webhooks?per_page=10');

        $response->assertOk()
            ->assertJsonCount(10, 'data')
            ->assertJsonPath('meta.pagination.total', 25);
    }
}
