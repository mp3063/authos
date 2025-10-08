<?php

namespace Database\Factories;

use App\Models\FailedLoginAttempt;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\FailedLoginAttempt>
 */
class FailedLoginAttemptFactory extends Factory
{
    protected $model = FailedLoginAttempt::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'email' => fake()->safeEmail(),
            'ip_address' => fake()->ipv4(),
            'user_agent' => fake()->userAgent(),
            'attempt_type' => fake()->randomElement(['password', 'mfa', 'social']),
            'failure_reason' => fake()->randomElement([
                'Invalid credentials',
                'Account locked',
                'Invalid MFA code',
                'Social provider error',
            ]),
            'metadata' => [
                'device' => fake()->randomElement(['desktop', 'mobile', 'tablet']),
                'os' => fake()->randomElement(['Windows', 'macOS', 'Linux', 'iOS', 'Android']),
            ],
            'attempted_at' => fake()->dateTimeBetween('-30 days', 'now'),
        ];
    }

    /**
     * Indicate that the attempt was for password authentication.
     */
    public function password(): static
    {
        return $this->state(fn (array $attributes) => [
            'attempt_type' => 'password',
            'failure_reason' => 'Invalid credentials',
        ]);
    }

    /**
     * Indicate that the attempt was for MFA.
     */
    public function mfa(): static
    {
        return $this->state(fn (array $attributes) => [
            'attempt_type' => 'mfa',
            'failure_reason' => 'Invalid MFA code',
        ]);
    }

    /**
     * Indicate that the attempt was for social login.
     */
    public function social(): static
    {
        return $this->state(fn (array $attributes) => [
            'attempt_type' => 'social',
            'failure_reason' => 'Social provider error',
        ]);
    }

    /**
     * Indicate that the attempt was recent.
     */
    public function recent(): static
    {
        return $this->state(fn (array $attributes) => [
            'attempted_at' => now()->subMinutes(fake()->numberBetween(1, 60)),
        ]);
    }

    /**
     * Indicate that the attempt was for a specific IP address.
     */
    public function forIp(string $ip): static
    {
        return $this->state(fn (array $attributes) => [
            'ip_address' => $ip,
        ]);
    }

    /**
     * Indicate that the attempt was for a specific email.
     */
    public function forEmail(string $email): static
    {
        return $this->state(fn (array $attributes) => [
            'email' => $email,
        ]);
    }
}
