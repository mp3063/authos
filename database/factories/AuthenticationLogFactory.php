<?php

namespace Database\Factories;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\AuthenticationLog>
 */
class AuthenticationLogFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $events = [
            'login_success', 'logout', 'login_failed', 'password_reset', 'password_changed',
            'mfa_enabled', 'mfa_disabled', 'mfa_verified', 'account_locked',
            'account_unlocked', 'email_verified', 'profile_updated',
        ];

        $event = fake()->randomElement($events);
        $success = ! in_array($event, ['login_failed', 'account_locked']);

        return [
            'user_id' => User::factory(),
            'event' => $event,
            'ip_address' => fake()->ipv4(),
            'user_agent' => fake()->userAgent(),
            'success' => $success,
            'details' => [
                'method' => fake()->randomElement(['password', 'oauth', 'sso', 'api_token']),
                'device_type' => fake()->randomElement(['desktop', 'mobile', 'tablet']),
                'browser' => fake()->randomElement(['Chrome', 'Firefox', 'Safari', 'Edge']),
                'location' => fake()->city().', '.fake()->country(),
                'risk_score' => fake()->numberBetween(0, 100),
            ],
            'created_at' => fake()->dateTimeBetween('-30 days', 'now'),
        ];
    }

    /**
     * Create failed login attempt.
     */
    public function failedLogin(): static
    {
        return $this->state(fn (array $attributes) => [
            'event' => 'login_failed',
            'success' => false,
            'details' => array_merge($attributes['details'] ?? [], [
                'failure_reason' => fake()->randomElement(['invalid_password', 'invalid_email', 'account_locked', 'mfa_required']),
                'attempt_count' => fake()->numberBetween(1, 5),
            ]),
        ]);
    }

    /**
     * Create successful login.
     */
    public function successfulLogin(): static
    {
        return $this->state(fn (array $attributes) => [
            'event' => 'login_success',
            'success' => true,
        ]);
    }

    /**
     * Create logout event.
     */
    public function logout(): static
    {
        return $this->state(fn (array $attributes) => [
            'event' => 'logout',
            'success' => true,
        ]);
    }

    /**
     * Create MFA-related event.
     */
    public function mfaEvent(string $event = 'mfa_verified'): static
    {
        return $this->state(function (array $attributes) use ($event) {
            $details = $attributes['details'] ?? [];
            $details['mfa_method'] = fake()->randomElement(['totp', 'sms', 'email']);

            return [
                'event' => $event,
                'success' => ! in_array($event, ['mfa_failed']),
                'details' => $details,
            ];
        });
    }

    /**
     * Create log for specific user.
     */
    public function forUser(User $user): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => $user->id,
        ]);
    }

    /**
     * Create log from specific IP.
     */
    public function fromIp(string $ip): static
    {
        return $this->state(fn (array $attributes) => [
            'ip_address' => $ip,
        ]);
    }

    /**
     * Create high-risk event.
     */
    public function highRisk(): static
    {
        return $this->state(function (array $attributes) {
            $details = $attributes['details'] ?? [];
            $details['risk_score'] = fake()->numberBetween(80, 100);
            $details['risk_factors'] = fake()->randomElements([
                'unusual_location', 'new_device', 'suspicious_user_agent',
                'multiple_failed_attempts', 'tor_network', 'vpn_detected',
            ], fake()->numberBetween(1, 3));

            return ['details' => $details];
        });
    }

    /**
     * Create recent event.
     */
    public function recent(): static
    {
        return $this->state(fn (array $attributes) => [
            'created_at' => fake()->dateTimeBetween('-1 hour', 'now'),
        ]);
    }
}
