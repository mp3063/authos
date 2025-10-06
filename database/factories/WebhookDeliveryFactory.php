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
            'event_type' => 'user.created',
            'payload' => [
                'event' => 'user.created',
                'data' => [
                    'id' => $this->faker->randomNumber(),
                    'email' => $this->faker->email(),
                ],
                'timestamp' => now()->toIso8601String(),
            ],
            'status' => 'success',
            'http_status_code' => 200,
            'response_body' => json_encode(['status' => 'received']),
            'request_duration_ms' => $this->faker->numberBetween(50, 500),
            'error_message' => null,
            'attempt_number' => 1,
            'max_attempts' => 6,
            'signature' => hash_hmac('sha256', 'test_payload', 'test_secret'),
            'next_retry_at' => null,
            'sent_at' => now(),
            'completed_at' => now(),
        ];
    }

    public function failed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'failed',
            'http_status_code' => 500,
            'response_body' => json_encode(['error' => 'Internal Server Error']),
            'error_message' => 'Server returned 500 error',
            'next_retry_at' => now()->addMinutes(5),
            'completed_at' => now(),
        ]);
    }

    public function retrying(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'retrying',
            'attempt_number' => 2,
            'next_retry_at' => now()->addMinutes(5),
        ]);
    }

    public function withAttempts(int $attempts): static
    {
        return $this->state(fn (array $attributes) => [
            'attempt_number' => $attempts,
        ]);
    }
}
