<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Organization>
 */
class OrganizationFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $name = fake()->company();

        return [
            'name' => $name,
            'slug' => Str::slug($name).'-'.fake()->unique()->numberBetween(1000, 9999),
            'is_active' => true,
            'settings' => [
                'require_mfa' => fake()->boolean(30),
                'password_policy' => [
                    'min_length' => fake()->numberBetween(8, 12),
                    'require_uppercase' => fake()->boolean(80),
                    'require_lowercase' => fake()->boolean(80),
                    'require_numbers' => fake()->boolean(70),
                    'require_symbols' => fake()->boolean(50),
                ],
                'session_timeout' => fake()->randomElement([30, 60, 120, 480, 1440]),
                'allowed_domains' => [],
                'sso_enabled' => fake()->boolean(20),
            ],
        ];
    }

    /**
     * Indicate that the organization is inactive.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Indicate that the organization requires MFA.
     */
    public function requiresMfa(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['require_mfa'] = true;

            return ['settings' => $settings];
        });
    }

    /**
     * Indicate that the organization has SSO enabled.
     */
    public function withSso(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['sso_enabled'] = true;

            return ['settings' => $settings];
        });
    }

    /**
     * Create organization with strict security settings.
     */
    public function highSecurity(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['require_mfa'] = true;
            $settings['password_policy'] = [
                'min_length' => 12,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_symbols' => true,
            ];
            $settings['session_timeout'] = 30;

            return ['settings' => $settings];
        });
    }
}
