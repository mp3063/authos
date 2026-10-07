<?php

namespace Database\Factories;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends Factory<SSOConfiguration>
 */
class SSOConfigurationFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'application_id' => Application::factory(),
            'logout_url' => fake()->url().'/logout',
            'callback_url' => fake()->url().'/callback',
            'allowed_domains' => [
                fake()->domainName(),
                fake()->domainName(),
                fake()->domainName(),
            ],
            'session_lifetime' => fake()->numberBetween(1800, 86400), // 30 min to 24 hours
            'settings' => [
                'auto_redirect' => fake()->boolean(),
                'require_ssl' => true,
                'enforce_https' => fake()->boolean(90),
                'max_sessions_per_user' => fake()->numberBetween(1, 5),
            ],
            'is_active' => true,
        ];
    }

    /**
     * Create configuration for specific application.
     */
    public function forApplication(Application $application): static
    {
        return $this->state(fn () => [
            'application_id' => $application->id,
        ]);
    }

    /**
     * Create configuration with specific session lifetime.
     */
    public function withSessionLifetime(int $seconds): static
    {
        return $this->state(fn () => [
            'session_lifetime' => $seconds,
        ]);
    }

    /**
     * Create configuration with specific allowed domains.
     */
    public function withAllowedDomains(array $domains): static
    {
        return $this->state(fn () => [
            'allowed_domains' => $domains,
        ]);
    }

    /**
     * Create configuration with auto-redirect enabled.
     */
    public function withAutoRedirect(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['auto_redirect'] = true;

            return ['settings' => $settings];
        });
    }

    /**
     * Create inactive configuration.
     */
    public function inactive(): static
    {
        return $this->state(fn () => [
            'is_active' => false,
        ]);
    }

    /**
     * Create configuration for organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(function () use ($organization) {
            // Create an application for this organization if not already set
            $application = Application::factory()->forOrganization($organization)->create();

            return [
                'application_id' => $application->id,
            ];
        });
    }

    /**
     * Create OIDC configuration.
     */
    public function oidc(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['provider_type'] = 'oidc';
            $settings['authorization_endpoint'] = fake()->url().'/oauth/authorize';
            $settings['token_endpoint'] = fake()->url().'/oauth/token';
            $settings['userinfo_endpoint'] = fake()->url().'/oauth/userinfo';
            $settings['jwks_endpoint'] = fake()->url().'/oauth/jwks';

            $configuration = [
                'authorization_endpoint' => $settings['authorization_endpoint'],
                'token_endpoint' => $settings['token_endpoint'],
                'userinfo_endpoint' => $settings['userinfo_endpoint'],
                'jwks_endpoint' => $settings['jwks_endpoint'],
                'client_id' => 'test-client-'.fake()->uuid(),
                'client_secret' => 'test-secret-'.Str::random(32),
            ];

            return [
                'provider' => 'oidc',
                'settings' => $settings,
                'configuration' => $configuration,
            ];
        });
    }

    /**
     * Create SAML 2.0 configuration.
     */
    public function saml2(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['provider_type'] = 'saml2';
            $settings['saml_sso_url'] = fake()->url().'/saml/sso';
            $settings['saml_sls_url'] = fake()->url().'/saml/sls';
            $settings['saml_entity_id'] = fake()->url().'/saml/metadata';
            $settings['x509_cert'] = 'test-certificate-content';
            $settings['name_id_format'] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

            return [
                'provider' => 'saml2',
                'settings' => $settings,
                'configuration' => [
                    'sso_url' => fake()->url().'/saml/sso',
                    'sls_url' => fake()->url().'/saml/sls',
                    'entity_id' => fake()->url().'/saml/metadata',
                    'x509_cert' => 'test-certificate-content',
                ],
            ];
        });
    }
}
