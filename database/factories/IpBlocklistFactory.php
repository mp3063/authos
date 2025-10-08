<?php

namespace Database\Factories;

use App\Models\IpBlocklist;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\IpBlocklist>
 */
class IpBlocklistFactory extends Factory
{
    protected $model = IpBlocklist::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $blockType = fake()->randomElement(['temporary', 'permanent', 'suspicious']);

        return [
            'ip_address' => fake()->ipv4(),
            'block_type' => $blockType,
            'reason' => $this->getReasonForType($blockType),
            'description' => fake()->sentence(),
            'blocked_at' => now(),
            'expires_at' => $blockType === 'temporary' ? now()->addHours(24) : null,
            'blocked_by' => null,
            'incident_count' => fake()->numberBetween(1, 50),
            'metadata' => [
                'trigger' => fake()->randomElement(['manual', 'automatic', 'security_incident']),
                'detected_patterns' => fake()->randomElement(['brute_force', 'sql_injection', 'xss']),
            ],
            'is_active' => true,
        ];
    }

    /**
     * Get a realistic reason for the block type.
     */
    protected function getReasonForType(string $type): string
    {
        $reasons = [
            'temporary' => 'Multiple failed login attempts',
            'permanent' => 'Known malicious IP address',
            'suspicious' => 'Suspicious activity detected',
        ];

        return $reasons[$type] ?? 'Security concern';
    }

    /**
     * Indicate that the block is temporary.
     */
    public function temporary(int $hoursUntilExpiry = 24): static
    {
        return $this->state(fn (array $attributes) => [
            'block_type' => 'temporary',
            'reason' => 'Multiple failed login attempts',
            'expires_at' => now()->addHours($hoursUntilExpiry),
        ]);
    }

    /**
     * Indicate that the block is permanent.
     */
    public function permanent(): static
    {
        return $this->state(fn (array $attributes) => [
            'block_type' => 'permanent',
            'reason' => 'Known malicious IP address',
            'expires_at' => null,
        ]);
    }

    /**
     * Indicate that the block is for suspicious activity.
     */
    public function suspicious(): static
    {
        return $this->state(fn (array $attributes) => [
            'block_type' => 'suspicious',
            'reason' => 'Suspicious activity detected',
            'expires_at' => now()->addHours(48),
        ]);
    }

    /**
     * Indicate that the block is active.
     */
    public function active(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => true,
            'blocked_at' => now()->subHours(1),
            'expires_at' => $attributes['expires_at'] ?? now()->addHours(23),
        ]);
    }

    /**
     * Indicate that the block is inactive.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Indicate that the block has expired.
     */
    public function expired(): static
    {
        return $this->state(fn (array $attributes) => [
            'blocked_at' => now()->subDays(2),
            'expires_at' => now()->subDay(),
            'is_active' => false,
        ]);
    }

    /**
     * Indicate that the block was created by an admin.
     */
    public function blockedByAdmin(?User $admin = null): static
    {
        return $this->state(fn (array $attributes) => [
            'blocked_by' => $admin?->id ?? User::factory()->create()->id,
            'metadata' => array_merge($attributes['metadata'] ?? [], [
                'trigger' => 'manual',
                'admin_notes' => 'Blocked by administrator',
            ]),
        ]);
    }

    /**
     * Indicate that the block is for a specific IP address.
     */
    public function forIp(string $ip): static
    {
        return $this->state(fn (array $attributes) => [
            'ip_address' => $ip,
        ]);
    }

    /**
     * Indicate a higher incident count.
     */
    public function withIncidentCount(int $count): static
    {
        return $this->state(fn (array $attributes) => [
            'incident_count' => $count,
        ]);
    }
}
