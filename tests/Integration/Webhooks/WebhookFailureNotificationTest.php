<?php

namespace Tests\Integration\Webhooks;

use App\Jobs\ProcessDeadLetterWebhookJob;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Notifications\WebhookAutoDisabledNotification;
use App\Services\WebhookDeliveryService;
use Illuminate\Support\Facades\Notification;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class WebhookFailureNotificationTest extends IntegrationTestCase
{
    private User $owner;

    private User $admin;

    private User $member;

    private Webhook $webhook;

    protected function setUp(): void
    {
        parent::setUp();

        $organization = Organization::factory()->create();
        $this->owner = $this->createUser(['organization_id' => $organization->id], 'Organization Owner');
        $this->admin = $this->createUser(['organization_id' => $organization->id], 'Organization Admin');
        $this->member = $this->createUser(['organization_id' => $organization->id], 'Organization Member');
        $this->webhook = Webhook::factory()->create(['organization_id' => $organization->id, 'consecutive_failures' => 10]);

        Notification::fake();
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
    }

    #[Test]
    public function it_notifies_webhook_managers_when_a_webhook_is_dead_lettered(): void
    {
        $delivery = WebhookDelivery::factory()->failed()->create(['webhook_id' => $this->webhook->id]);

        (new ProcessDeadLetterWebhookJob($delivery))->handle();

        $this->assertManagersNotifiedOnly();
        $this->assertNull(app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    #[Test]
    public function it_notifies_webhook_managers_when_a_webhook_is_auto_disabled(): void
    {
        $delivery = WebhookDelivery::factory()->failed()->create(['webhook_id' => $this->webhook->id]);

        app(WebhookDeliveryService::class)->moveToDeadLetter($delivery);

        $this->assertManagersNotifiedOnly();
        $this->assertNull(app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    private function assertManagersNotifiedOnly(): void
    {
        Notification::assertSentTo($this->owner, WebhookAutoDisabledNotification::class);
        Notification::assertSentTo($this->admin, WebhookAutoDisabledNotification::class);
        Notification::assertNotSentTo($this->member, WebhookAutoDisabledNotification::class);
    }
}
