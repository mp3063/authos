<?php

namespace Database\Factories;

use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<WebhookDelivery>
 */
class WebhookDeliveryFactory extends Factory
{
    protected $model = WebhookDelivery::class;

    public function definition(): array
    {
        return [
            'webhook_id' => Webhook::factory(),
            'event' => 'user.created',
            'payload' => json_encode([
                'event' => 'user.created',
                'data' => [
                    'id' => $this->faker->randomNumber(),
                    'email' => $this->faker->email(),
                ],
                'timestamp' => now()->toIso8601String(),
            ]),
            'status' => 'success',
            'response_status' => 200,
            'response_body' => json_encode(['status' => 'received']),
            'response_time_ms' => $this->faker->numberBetween(50, 500),
            'error_message' => null,
            'attempt' => 0,
            'will_retry' => false,
            'moved_to_dead_letter_at' => null,
        ];
    }

    public function failed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'failed',
            'response_status' => 500,
            'response_body' => json_encode(['error' => 'Internal Server Error']),
            'error_message' => 'Server returned 500 error',
            'will_retry' => true,
        ]);
    }

    public function deadLetter(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'dead_letter',
            'attempt' => 5,
            'will_retry' => false,
            'moved_to_dead_letter_at' => now(),
        ]);
    }

    public function withAttempts(int $attempts): static
    {
        return $this->state(fn (array $attributes) => [
            'attempt' => $attempts,
        ]);
    }
}
