<?php

namespace Tests\Integration\Webhooks;

use App\Models\CustomRole;
use App\Models\Webhook;
use App\Models\WebhookEvent;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class WebhookSecretVisibilityTest extends IntegrationTestCase
{
    #[Test]
    public function it_hides_webhook_secrets_from_callers_who_cannot_update_webhooks(): void
    {
        $reader = $this->createUser([], 'User', 'api');
        CustomRole::factory()->forOrganization($reader->organization)
            ->create(['permissions' => ['webhooks.read']])
            ->assignToUser($reader);
        $webhook = Webhook::factory()->create(['organization_id' => $reader->organization_id]);
        $this->actingAsApiUserWithToken($reader);

        $response = $this->getJson('/api/v1/webhooks')->assertOk();

        $this->assertSame([$webhook->id], collect($response->json('data'))->pluck('id')->all());
        $response->assertJsonMissingPath('data.0.secret');
    }

    #[Test]
    public function it_does_not_return_the_webhook_secret_to_a_read_only_caller(): void
    {
        $reader = $this->createUser([], 'User', 'api');
        CustomRole::factory()->forOrganization($reader->organization)
            ->create(['permissions' => ['webhooks.read']])
            ->assignToUser($reader);
        $webhook = Webhook::factory()->create(['organization_id' => $reader->organization_id]);
        $this->actingAsApiUserWithToken($reader);

        $this->getJson("/api/v1/webhooks/{$webhook->id}")
            ->assertOk()
            ->assertJsonPath('data.id', $webhook->id)
            ->assertJsonMissingPath('data.secret');
    }

    #[Test]
    public function it_shows_webhook_secrets_to_callers_who_can_update_them(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $webhook = Webhook::factory()->create(['organization_id' => $admin->organization_id]);
        $this->actingAsApiUserWithToken($admin);

        $this->getJson('/api/v1/webhooks')
            ->assertOk()
            ->assertJsonPath('data.0.secret', $webhook->secret);
    }

    #[Test]
    public function it_still_returns_the_secret_once_on_create_and_rotate(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        WebhookEvent::create(['name' => 'user.created', 'category' => 'user', 'description' => 'A user was created', 'is_active' => true, 'version' => '1.0']);
        $this->actingAsApiUserWithToken($admin);

        $created = $this->postJson('/api/v1/webhooks', [
            'name' => 'Hook',
            'url' => 'https://example.com/hook',
            'events' => ['user.created'],
        ])->assertCreated();
        $this->assertNotEmpty($created->json('data.secret'));

        $rotated = $this->postJson('/api/v1/webhooks/'.$created->json('data.id').'/rotate-secret')->assertOk();
        $this->assertNotEmpty($rotated->json('data.secret'));
        $this->assertNotSame($created->json('data.secret'), $rotated->json('data.secret'));
    }
}
