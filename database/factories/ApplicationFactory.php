<?php

namespace Database\Factories;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Laravel\Passport\Client;

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
            'name' => fake()->company().' '.fake()->randomElement(['App', 'Portal', 'Dashboard', 'Platform']),
            'organization_id' => Organization::factory(),
            'client_id' => (string) Str::uuid(),
            'client_secret' => Str::random(40),
            'redirect_uris' => [
                'http://localhost:3000/auth/callback',
                'http://localhost:8000/auth/callback',
                fake()->url().'/callback',
            ],
            'allowed_origins' => [
                'http://localhost:3000',
                'http://localhost:8000',
                fake()->url(),
            ],
            'allowed_grant_types' => fake()->randomElements(['authorization_code', 'refresh_token', 'client_credentials', 'password'], fake()->numberBetween(1, 3)),
            'webhook_url' => fake()->optional()->url().'/webhook',
            'settings' => [
                'description' => fake()->sentence(),
                'logo' => fake()->optional()->imageUrl(150, 150, 'technics'),
                'homepage_url' => fake()->optional()->url(),
                'privacy_policy_url' => fake()->optional()->url().'/privacy',
                'terms_of_service_url' => fake()->optional()->url().'/terms',
                'scopes' => fake()->randomElements(['openid', 'profile', 'email', 'read', 'write'], fake()->numberBetween(2, 5)),
            ],
            'is_active' => true,
        ];
    }

    /**
     * Configure the model factory to create a Passport client after creating the application.
     */
    public function configure(): static
    {
        return $this->afterCreating(function ($application) {
            // Create Passport client if not already set
            if (! $application->passport_client_id) {
                $passportClient = Client::create([
                    'name' => $application->name,
                    'secret' => $application->client_secret, // Passport will auto-hash this
                    'redirect' => implode(',', $application->redirect_uris),
                    'personal_access_client' => false,
                    'password_client' => in_array('password', $application->allowed_grant_types ?? []),
                    'revoked' => false,
                ]);

                // Update application with passport_client_id
                $application->update(['passport_client_id' => $passportClient->id]);
            }
        });
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
     * Set specific allowed grant types for the application.
     */
    public function withGrantTypes(array $grantTypes): static
    {
        return $this->state(fn (array $attributes) => [
            'allowed_grant_types' => $grantTypes,
        ]);
    }

    /**
     * Set specific scopes for the application (stored in settings).
     */
    public function withScopes(array $scopes): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['scopes'] = $scopes;

            return ['settings' => $settings];
        });
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
            $grantTypes = $attributes['allowed_grant_types'] ?? [];
            if (! in_array('password', $grantTypes)) {
                $grantTypes[] = 'password';
            }

            return ['allowed_grant_types' => $grantTypes];
        });
    }

    /**
     * Create application with client credentials grant support.
     */
    public function withClientCredentials(): static
    {
        return $this->state(function (array $attributes) {
            $grantTypes = $attributes['allowed_grant_types'] ?? [];
            if (! in_array('client_credentials', $grantTypes)) {
                $grantTypes[] = 'client_credentials';
            }

            return ['allowed_grant_types' => $grantTypes];
        });
    }

    /**
     * Create application with specific webhook URL.
     */
    public function withWebhook(string $webhookUrl): static
    {
        return $this->state(fn (array $attributes) => [
            'webhook_url' => $webhookUrl,
        ]);
    }

    /**
     * Create application with allowed origins.
     */
    public function withAllowedOrigins(array $origins): static
    {
        return $this->state(fn (array $attributes) => [
            'allowed_origins' => $origins,
        ]);
    }
}
