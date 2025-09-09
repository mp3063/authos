<?php

namespace Database\Factories;

use App\Models\Application;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\SSOSession>
 */
class SSOSessionFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'application_id' => Application::factory(),
            'session_token' => Str::random(64),
            'refresh_token' => Str::random(64),
            'external_session_id' => Str::uuid(),
            'ip_address' => fake()->ipv4(),
            'user_agent' => fake()->userAgent(),
            'expires_at' => now()->addHours(2),
            'last_activity_at' => now()->subMinutes(fake()->numberBetween(1, 60)),
            'metadata' => [
                'login_method' => fake()->randomElement(['password', 'sso', 'oauth']),
                'device_type' => fake()->randomElement(['desktop', 'mobile', 'tablet']),
                'browser' => fake()->randomElement(['Chrome', 'Firefox', 'Safari', 'Edge']),
                'os' => fake()->randomElement(['Windows', 'macOS', 'Linux', 'iOS', 'Android']),
            ],
        ];
    }

    /**
     * Indicate that the session is expired.
     */
    public function expired(): static
    {
        return $this->state(fn (array $attributes) => [
            'expires_at' => now()->subHours(1),
            'last_activity_at' => now()->subHours(2),
        ]);
    }

    /**
     * Create session for specific user.
     */
    public function forUser(User $user): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => $user->id,
        ]);
    }

    /**
     * Create session for specific application.
     */
    public function forApplication(Application $application): static
    {
        return $this->state(fn (array $attributes) => [
            'application_id' => $application->id,
        ]);
    }

    /**
     * Create recently active session.
     */
    public function recentlyActive(): static
    {
        return $this->state(fn (array $attributes) => [
            'last_activity_at' => now()->subMinutes(fake()->numberBetween(1, 5)),
            'expires_at' => now()->addHours(fake()->numberBetween(1, 8)),
        ]);
    }

    /**
     * Create session with specific IP address.
     */
    public function fromIp(string $ip): static
    {
        return $this->state(fn (array $attributes) => [
            'ip_address' => $ip,
        ]);
    }

    /**
     * Create mobile session.
     */
    public function mobile(): static
    {
        return $this->state(function (array $attributes) {
            $metadata = $attributes['metadata'] ?? [];
            $metadata['device_type'] = 'mobile';
            $metadata['os'] = fake()->randomElement(['iOS', 'Android']);

            return [
                'metadata' => $metadata,
                'user_agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15',
            ];
        });
    }
}
