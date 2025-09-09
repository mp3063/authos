<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\User>
 */
class UserFactory extends Factory
{
    /**
     * The current password being used by the factory.
     */
    protected static ?string $password;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'email_verified_at' => now(),
            'password' => static::$password ??= Hash::make('password'),
            'avatar' => fake()->optional()->imageUrl(200, 200, 'people'),
            'profile' => [
                'bio' => fake()->optional()->paragraph(),
                'location' => fake()->optional()->city(),
                'website' => fake()->optional()->url(),
                'phone' => fake()->optional()->phoneNumber(),
            ],
            'organization_id' => null, // Will be set by relations or states
            'is_active' => true,
            'password_changed_at' => now()->subDays(fake()->numberBetween(1, 365)),
            'remember_token' => Str::random(10),
        ];
    }

    /**
     * Indicate that the model's email address should be unverified.
     */
    public function unverified(): static
    {
        return $this->state(fn (array $attributes) => [
            'email_verified_at' => null,
        ]);
    }

    /**
     * Indicate that the user has MFA enabled.
     */
    public function withMfa(): static
    {
        return $this->state(fn (array $attributes) => [
            'two_factor_secret' => 'test-secret-'.Str::random(10),
            'two_factor_confirmed_at' => now(),
            'two_factor_recovery_codes' => json_encode([
                'code1', 'code2', 'code3', 'code4',
                'code5', 'code6', 'code7', 'code8',
            ]),
            'mfa_methods' => ['totp'],
        ]);
    }

    /**
     * Indicate that the user is inactive.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Create a user with specific organization.
     */
    public function forOrganization(\App\Models\Organization $organization): static
    {
        return $this->state(fn (array $attributes) => [
            'organization_id' => $organization->id,
        ]);
    }
}
