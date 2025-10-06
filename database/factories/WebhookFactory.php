<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\Webhook;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Webhook>
 */
class WebhookFactory extends Factory
{
    protected $model = Webhook::class;

    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'url' => $this->faker->url(),
            'events' => ['user.created', 'user.updated'],
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'is_active' => true,
            'description' => $this->faker->sentence(),
            'delivery_stats' => [
                'total_deliveries' => 0,
                'successful_deliveries' => 0,
                'failed_deliveries' => 0,
                'average_response_time_ms' => 0,
            ],
            'consecutive_failures' => 0,
            'last_delivered_at' => null,
            'disabled_at' => null,
        ];
    }

    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
            'disabled_at' => now(),
        ]);
    }

    public function withFailures(int $count = 5): static
    {
        return $this->state(fn (array $attributes) => [
            'consecutive_failures' => $count,
            'delivery_stats' => [
                'total_deliveries' => $count,
                'successful_deliveries' => 0,
                'failed_deliveries' => $count,
                'average_response_time_ms' => 0,
            ],
        ]);
    }

    public function subscribeToEvent(string $event): static
    {
        return $this->state(fn (array $attributes) => [
            'events' => [$event],
        ]);
    }

    public function subscribeToAllEvents(): static
    {
        return $this->state(fn (array $attributes) => [
            'events' => ['*'],
        ]);
    }
}
