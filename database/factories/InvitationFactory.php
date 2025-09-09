<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Invitation>
 */
class InvitationFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'inviter_id' => User::factory(),
            'email' => fake()->unique()->safeEmail(),
            'token' => Str::random(32),
            'role' => fake()->randomElement(['user', 'organization admin', 'application admin']),
            'expires_at' => now()->addDays(7),
            'status' => 'pending',
            'accepted_at' => null,
            'accepted_by' => null,
            'declined_at' => null,
            'decline_reason' => null,
            'cancelled_at' => null,
            'cancelled_by' => null,
            'metadata' => [
                'invitation_message' => fake()->optional()->sentence(),
                'invited_at' => now()->toISOString(),
                'source' => fake()->randomElement(['admin_panel', 'bulk_invite', 'api']),
            ],
        ];
    }

    /**
     * Indicate that the invitation is expired.
     */
    public function expired(): static
    {
        return $this->state(function (array $attributes) {
            return [
                'expires_at' => now()->subDays(1),
                'status' => 'pending', // Still pending but expired by date
            ];
        });
    }

    /**
     * Indicate that the invitation is accepted.
     */
    public function accepted(): static
    {
        return $this->state(function (array $attributes) {
            return [
                'status' => 'accepted',
                'accepted_at' => fake()->dateTimeBetween('-7 days', 'now'),
                'accepted_by' => User::factory(),
            ];
        });
    }

    /**
     * Indicate that the invitation is declined.
     */
    public function declined(): static
    {
        return $this->state(function (array $attributes) {
            return [
                'status' => 'declined',
                'declined_at' => fake()->dateTimeBetween('-7 days', 'now'),
                'decline_reason' => fake()->optional()->sentence(),
            ];
        });
    }

    /**
     * Create invitation for specific organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(fn (array $attributes) => [
            'organization_id' => $organization->id,
        ]);
    }

    /**
     * Create invitation with specific role.
     */
    public function withRole(string $role): static
    {
        return $this->state(fn (array $attributes) => [
            'role' => $role,
        ]);
    }

    /**
     * Create invitation from specific inviter.
     */
    public function fromInviter(User $inviter): static
    {
        return $this->state(fn (array $attributes) => [
            'inviter_id' => $inviter->id,
        ]);
    }

    /**
     * Create invitation for specific email.
     */
    public function forEmail(string $email): static
    {
        return $this->state(fn (array $attributes) => [
            'email' => $email,
        ]);
    }

    /**
     * Create invitation with custom expiry.
     */
    public function expiresIn(int $days): static
    {
        return $this->state(fn (array $attributes) => [
            'expires_at' => now()->addDays($days),
        ]);
    }
}
