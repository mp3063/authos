<?php

namespace Tests\Integration\Webhooks;

use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Models\WebhookEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class WebhookAuthorizationTest extends IntegrationTestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function webhookEndpoints(): array
    {
        return [
            'show' => ['get', '/api/v1/webhooks/{id}'],
            'update' => ['put', '/api/v1/webhooks/{id}'],
            'destroy' => ['delete', '/api/v1/webhooks/{id}'],
            'test' => ['post', '/api/v1/webhooks/{id}/test'],
            'rotate secret' => ['post', '/api/v1/webhooks/{id}/rotate-secret'],
            'enable' => ['post', '/api/v1/webhooks/{id}/enable'],
            'disable' => ['post', '/api/v1/webhooks/{id}/disable'],
            'deliveries' => ['get', '/api/v1/webhooks/{id}/deliveries'],
            'stats' => ['get', '/api/v1/webhooks/{id}/stats'],
        ];
    }

    #[Test]
    #[DataProvider('webhookEndpoints')]
    public function it_refuses_roles_without_webhook_permissions(string $method, string $url): void
    {
        foreach (['Application Manager', 'Auditor', 'User'] as $role) {
            $user = $this->createUser([], $role, 'api');
            $webhook = Webhook::factory()->create(['organization_id' => $user->organization_id]);
            $this->actingAsApiUserWithToken($user);

            $this->json($method, str_replace('{id}', (string) $webhook->id, $url), ['name' => 'Renamed'])->assertForbidden();

            $this->assertModelExists($webhook);
            $this->assertNotSame('Renamed', $webhook->fresh()->name);
        }
    }

    #[Test]
    #[DataProvider('webhookEndpoints')]
    public function it_hides_another_organizations_webhook_with_404(string $method, string $url): void
    {
        $owner = $this->createApiOrganizationOwner();
        $foreign = Webhook::factory()->create();
        $this->actingAsApiUserWithToken($owner);

        $this->json($method, str_replace('{id}', (string) $foreign->id, $url), ['name' => 'Renamed'])->assertNotFound();

        $this->assertModelExists($foreign);
        $this->assertNotSame('Renamed', $foreign->fresh()->name);
    }

    #[Test]
    public function it_refuses_the_roles_without_webhook_permissions_on_the_collection(): void
    {
        foreach (['Application Manager', 'Auditor', 'User'] as $role) {
            $this->actingAsApiUserWithToken($this->createUser([], $role, 'api'));

            $this->getJson('/api/v1/webhooks')->assertForbidden();
            $this->postJson('/api/v1/webhooks', [
                'name' => 'Hook',
                'url' => 'https://example.com/hook',
                'events' => ['user.created'],
            ])->assertForbidden();
        }
    }

    #[Test]
    public function it_refuses_creating_a_webhook_for_a_user_without_an_organization(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $owner->forceFill(['organization_id' => null])->save();
        $this->actingAsApiUserWithToken($owner->fresh());

        $this->postJson('/api/v1/webhooks', [
            'name' => 'Hook',
            'url' => 'https://example.com/hook',
            'events' => ['user.created'],
        ])->assertForbidden();

        $this->assertDatabaseMissing('webhooks', ['url' => 'https://example.com/hook']);
    }

    #[Test]
    public function it_lists_only_own_organization_webhooks_for_an_organization_admin(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $own = Webhook::factory()->create(['organization_id' => $admin->organization_id]);
        Webhook::factory()->create();
        $this->actingAsApiUserWithToken($admin);

        $response = $this->getJson('/api/v1/webhooks')->assertOk();

        $this->assertSame([$own->id], collect($response->json('data'))->pluck('id')->all());
    }

    #[Test]
    public function it_lets_a_super_admin_read_any_organizations_webhook(): void
    {
        $superAdmin = $this->createApiSuperAdmin();
        $foreign = Webhook::factory()->create();
        $this->actingAsApiUserWithToken($superAdmin);

        $this->getJson("/api/v1/webhooks/{$foreign->id}")->assertOk();
    }

    #[Test]
    public function it_refuses_retrying_a_delivery_to_roles_without_webhooks_update(): void
    {
        $user = $this->createUser([], 'Auditor', 'api');
        $delivery = $this->createFailedDelivery($user->organization_id);
        $this->actingAsApiUserWithToken($user);

        $this->postJson("/api/v1/webhooks/deliveries/{$delivery->id}/retry")->assertForbidden();
        $this->postJson("/api/v1/webhook-deliveries/{$delivery->id}/retry")->assertForbidden();

        $this->assertSame(1, $delivery->fresh()->attempt_number);
    }

    #[Test]
    public function it_refuses_retrying_another_organizations_delivery(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $delivery = $this->createFailedDelivery($this->createOrganization()->id);
        $this->actingAsApiUserWithToken($owner);

        $this->postJson("/api/v1/webhook-deliveries/{$delivery->id}/retry")->assertForbidden();

        $this->assertSame(1, $delivery->fresh()->attempt_number);
    }

    #[Test]
    public function it_returns_404_for_a_missing_delivery(): void
    {
        $this->actingAsApiUserWithToken($this->createApiOrganizationOwner());

        $this->postJson('/api/v1/webhook-deliveries/999999/retry')->assertNotFound();
    }

    #[Test]
    public function it_hides_another_organizations_delivery_detail_with_404(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $delivery = $this->createFailedDelivery($this->createOrganization()->id);
        $this->actingAsApiUserWithToken($owner);

        $this->getJson("/api/v1/webhooks/{$delivery->webhook_id}/deliveries/{$delivery->id}")->assertNotFound();
    }

    #[Test]
    public function it_lets_an_organization_admin_read_own_delivery_detail(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $delivery = $this->createFailedDelivery($admin->organization_id);
        $this->actingAsApiUserWithToken($admin);

        $this->getJson("/api/v1/webhooks/{$delivery->webhook_id}/deliveries/{$delivery->id}")->assertOk();
    }

    #[Test]
    public function it_lets_any_authenticated_user_read_webhook_events(): void
    {
        $event = WebhookEvent::create(['name' => 'user.created', 'category' => 'user', 'description' => 'A user was created', 'is_active' => true, 'version' => '1.0']);
        $this->actingAsApiUserWithToken($this->createApiUser());

        $this->getJson('/api/v1/webhook-events')->assertOk();
        $this->getJson("/api/v1/webhook-events/{$event->id}")->assertOk();
    }

    private function createFailedDelivery(int $organizationId): WebhookDelivery
    {
        return WebhookDelivery::factory()->failed()->create([
            'webhook_id' => Webhook::factory()->create(['organization_id' => $organizationId])->id,
        ]);
    }
}
