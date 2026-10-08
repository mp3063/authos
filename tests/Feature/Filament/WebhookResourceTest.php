<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\WebhookResource\Pages\CreateWebhook;
use App\Models\WebhookEvent;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class WebhookResourceTest extends IntegrationTestCase
{
    #[Test]
    public function it_renders_the_create_form_with_event_options_from_several_categories(): void
    {
        WebhookEvent::create(['name' => 'user.created', 'category' => 'user', 'description' => 'A user was created', 'is_active' => true, 'version' => '1.0']);
        WebhookEvent::create(['name' => 'application.deleted', 'category' => 'application', 'description' => 'An application was deleted', 'is_active' => true, 'version' => '1.0']);

        $this->actingAs($this->createSuperAdmin());

        Livewire::test(CreateWebhook::class)
            ->assertSuccessful()
            ->assertSee('user.created - A user was created')
            ->assertSee('application.deleted - An application was deleted');
    }
}
