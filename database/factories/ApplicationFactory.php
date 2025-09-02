<?php

namespace Database\Factories;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Application>
 */
class ApplicationFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->company() . ' ' . fake()->randomElement(['App', 'Portal', 'Dashboard', 'Platform']),
            'description' => fake()->sentence(),
            'organization_id' => Organization::factory(),
            'client_id' => (string) Str::uuid(),
            'client_secret' => Str::random(40),
            'redirect_uris' => [
                'http://localhost:3000/auth/callback',
                'http://localhost:8000/auth/callback',
                fake()->url() . '/callback',
            ],
            'scopes' => fake()->randomElements(['openid', 'profile', 'email', 'read', 'write'], fake()->numberBetween(2, 5)),
            'is_active' => true,
            'grant_types' => ['authorization_code', 'refresh_token'],
            'logo' => fake()->optional()->imageUrl(150, 150, 'technics'),
            'homepage_url' => fake()->optional()->url(),
            'privacy_policy_url' => fake()->optional()->url() . '/privacy',
            'terms_of_service_url' => fake()->optional()->url() . '/terms',
        ];
    }

    /**
     * Indicate that the application is inactive.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Set specific scopes for the application.
     */
    public function withScopes(array $scopes): static
    {
        return $this->state(fn (array $attributes) => [
            'scopes' => $scopes,
        ]);
    }

    /**
     * Create application for specific organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(fn (array $attributes) => [
            'organization_id' => $organization->id,
        ]);
    }

    /**
     * Create application with password grant support.
     */
    public function withPasswordGrant(): static
    {
        return $this->state(function (array $attributes) {
            $grantTypes = $attributes['grant_types'] ?? [];
            if (!in_array('password', $grantTypes)) {
                $grantTypes[] = 'password';
            }
            
            return ['grant_types' => $grantTypes];
        });
    }

    /**
     * Create application with client credentials grant support.
     */
    public function withClientCredentials(): static
    {
        return $this->state(function (array $attributes) {
            $grantTypes = $attributes['grant_types'] ?? [];
            if (!in_array('client_credentials', $grantTypes)) {
                $grantTypes[] = 'client_credentials';
            }
            
            return ['grant_types' => $grantTypes];
        });
    }
}