<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\WebhookDeliveryResource\Pages\ListWebhookDeliveries;
use App\Filament\Resources\WebhookDeliveryResource\Pages\ViewWebhookDelivery;
use App\Filament\Resources\WebhookResource\Pages\ListWebhooks;
use App\Filament\Resources\WebhookResource\Pages\ViewWebhook;
use App\Jobs\DeliverWebhookJob;
use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class WebhookActionAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    private function actingAsReader(): void
    {
        $this->actingAs($this->createUserWithCustomPermissions($this->organization, ['webhooks.read']));
    }

    private function webhook(array $attributes = []): Webhook
    {
        return Webhook::factory()->create(['organization_id' => $this->organization->id] + $attributes);
    }

    #[Test]
    public function it_hides_and_forbids_webhook_actions_for_a_role_without_the_permission(): void
    {
        $this->actingAsReader();
        Http::fake();
        $active = $this->webhook(['is_active' => true]);
        $inactive = $this->webhook(['is_active' => false]);
        $secret = $active->secret;

        $list = Livewire::test(ListWebhooks::class)
            ->assertTableActionHidden('test', $active)
            ->assertTableActionHidden('rotate_secret', $active)
            ->assertTableActionHidden('disable', $active)
            ->assertTableActionHidden('enable', $inactive)
            ->assertTableBulkActionHidden('delete');
        $this->forceTableAction($list, 'test', $active);
        $this->forceTableAction($list, 'rotate_secret', $active);
        $this->forceTableAction($list, 'disable', $active);
        $this->forceTableAction($list, 'enable', $inactive);
        $this->forceTableBulkAction($list, 'enable', [$inactive]);
        $this->forceTableBulkAction($list, 'disable', [$active]);
        $this->forceTableBulkAction($list, 'delete', [$active]);

        $view = Livewire::test(ViewWebhook::class, ['record' => $active->getRouteKey()])->assertActionHidden('test');
        $this->forcePageAction($view, 'test');

        Http::assertNothingSent();
        $this->assertSame($secret, $active->fresh()->secret);
        $this->assertTrue($active->fresh()->is_active);
        $this->assertFalse($inactive->fresh()->is_active);
        $this->assertNotNull(Webhook::find($active->id));
    }

    #[Test]
    public function an_admin_can_rotate_disable_and_enable_a_webhook(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Admin'));
        $active = $this->webhook(['is_active' => true]);
        $inactive = $this->webhook(['is_active' => false]);
        $secret = $active->secret;

        Livewire::test(ListWebhooks::class)
            ->assertTableActionVisible('rotate_secret', $active)
            ->callTableAction('rotate_secret', $active)
            ->callTableAction('disable', $active)
            ->callTableAction('enable', $inactive);

        $this->assertNotSame($secret, $active->fresh()->secret);
        $this->assertFalse($active->fresh()->is_active);
        $this->assertTrue($inactive->fresh()->is_active);
    }

    #[Test]
    public function it_hides_and_forbids_delivery_retries_for_a_role_without_the_permission(): void
    {
        Queue::fake();
        $this->actingAsReader();
        $webhook = $this->webhook();
        $delivery = WebhookDelivery::factory()->failed()->create(['webhook_id' => $webhook->id]);

        $list = Livewire::test(ListWebhookDeliveries::class)->assertTableActionHidden('retry', $delivery);
        $this->forceTableAction($list, 'retry', $delivery);
        $this->forceTableBulkAction($list, 'retry_failed', [$delivery]);

        $view = Livewire::test(ViewWebhookDelivery::class, ['record' => $delivery->getRouteKey()])->assertActionHidden('retry');
        $this->forcePageAction($view, 'retry');

        Queue::assertNothingPushed();
        $this->assertSame('failed', $delivery->fresh()->status->value);
    }

    #[Test]
    public function an_admin_can_retry_a_failed_delivery(): void
    {
        Queue::fake();
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Admin'));
        $delivery = WebhookDelivery::factory()->failed()->create(['webhook_id' => $this->webhook()->id]);

        Livewire::test(ListWebhookDeliveries::class)
            ->assertTableActionVisible('retry', $delivery)
            ->callTableAction('retry', $delivery);

        Queue::assertPushed(DeliverWebhookJob::class);
        $this->assertSame('pending', $delivery->fresh()->status->value);
    }
}
