<?php

namespace Database\Seeders;

use App\Enums\WebhookEventType;
use App\Models\WebhookEvent;
use Illuminate\Database\Seeder;

class WebhookEventSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $events = WebhookEventType::cases();

        foreach ($events as $event) {
            WebhookEvent::updateOrCreate(
                ['name' => $event->value],
                [
                    'category' => $event->getCategory(),
                    'description' => $event->getDescription(),
                    'is_active' => true,
                    'version' => '1.0',
                ]
            );
        }

        $this->command->info('Webhook events seeded successfully.');
    }
}
