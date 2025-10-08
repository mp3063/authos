<?php

namespace Database\Factories;

use App\Models\AccountLockout;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\AccountLockout>
 */
class AccountLockoutFactory extends Factory
{
    protected $model = AccountLockout::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'email' => fake()->safeEmail(),
            'ip_address' => fake()->ipv4(),
            'lockout_type' => 'progressive',
            'attempt_count' => fake()->numberBetween(3, 15),
            'locked_at' => now(),
            'unlock_at' => now()->addMinutes(5),
            'unlocked_at' => null,
            'unlock_method' => null,
            'reason' => 'Too many failed login attempts',
            'metadata' => [
                'trigger' => 'failed_login_threshold',
                'lockout_duration_minutes' => 5,
            ],
        ];
    }

    /**
     * Indicate that the lockout is progressive.
     */
    public function progressive(int $attemptCount = 5, int $durationMinutes = 5): static
    {
        return $this->state(fn (array $attributes) => [
            'lockout_type' => 'progressive',
            'attempt_count' => $attemptCount,
            'unlock_at' => now()->addMinutes($durationMinutes),
            'reason' => 'Too many failed login attempts',
            'metadata' => [
                'trigger' => 'failed_login_threshold',
                'lockout_duration_minutes' => $durationMinutes,
            ],
        ]);
    }

    /**
     * Indicate that the lockout is permanent.
     */
    public function permanent(): static
    {
        return $this->state(fn (array $attributes) => [
            'lockout_type' => 'permanent',
            'unlock_at' => null,
            'reason' => 'Account permanently locked',
            'metadata' => [
                'trigger' => 'security_incident',
            ],
        ]);
    }

    /**
     * Indicate that the lockout was admin-initiated.
     */
    public function adminInitiated(): static
    {
        return $this->state(fn (array $attributes) => [
            'lockout_type' => 'admin_initiated',
            'unlock_at' => null,
            'reason' => 'Locked by administrator',
            'metadata' => [
                'admin_id' => User::factory()->create()->id,
                'admin_reason' => 'Security concern',
            ],
        ]);
    }

    /**
     * Indicate that the lockout is expired.
     */
    public function expired(): static
    {
        return $this->state(fn (array $attributes) => [
            'locked_at' => now()->subHours(2),
            'unlock_at' => now()->subHour(),
        ]);
    }

    /**
     * Indicate that the lockout is active.
     */
    public function active(): static
    {
        return $this->state(fn (array $attributes) => [
            'locked_at' => now()->subMinutes(10),
            'unlock_at' => now()->addMinutes(50),
            'unlocked_at' => null,
        ]);
    }

    /**
     * Indicate that the lockout has been unlocked.
     */
    public function unlocked(string $method = 'auto'): static
    {
        return $this->state(fn (array $attributes) => [
            'unlocked_at' => now(),
            'unlock_method' => $method,
        ]);
    }

    /**
     * Indicate that the lockout is without a user (email-based only).
     */
    public function withoutUser(): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => null,
        ]);
    }

    /**
     * Indicate that the lockout is for a specific user.
     */
    public function forUser(User $user): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => $user->id,
            'email' => $user->email,
        ]);
    }

    /**
     * Indicate that the lockout is for a specific IP address.
     */
    public function forIp(string $ip): static
    {
        return $this->state(fn (array $attributes) => [
            'ip_address' => $ip,
        ]);
    }
}
