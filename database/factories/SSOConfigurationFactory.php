<?php

namespace Database\Factories;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\SSOConfiguration>
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
        $providers = ['saml2', 'oidc', 'oauth2', 'ldap'];
        $provider = fake()->randomElement($providers);

        return [
            'organization_id' => Organization::factory(),
            'name' => fake()->company() . ' SSO',
            'provider' => $provider,
            'is_active' => true,
            'configuration' => $this->getConfigurationForProvider($provider),
            'metadata' => [
                'created_by' => 'system',
                'last_tested_at' => fake()->optional()->dateTimeBetween('-30 days', 'now'),
                'test_status' => fake()->randomElement(['success', 'failed', 'pending', null]),
            ],
        ];
    }

    /**
     * Get configuration based on provider type.
     */
    private function getConfigurationForProvider(string $provider): array
    {
        switch ($provider) {
            case 'saml2':
                return [
                    'entity_id' => fake()->url() . '/saml/metadata',
                    'sso_url' => fake()->url() . '/saml/sso',
                    'slo_url' => fake()->url() . '/saml/slo',
                    'x509_cert' => 'MIICert...',
                    'name_id_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                ];

            case 'oidc':
                return [
                    'issuer' => fake()->url(),
                    'client_id' => Str::random(20),
                    'client_secret' => Str::random(40),
                    'authorization_endpoint' => fake()->url() . '/auth',
                    'token_endpoint' => fake()->url() . '/token',
                    'userinfo_endpoint' => fake()->url() . '/userinfo',
                    'scopes' => ['openid', 'profile', 'email'],
                ];

            case 'oauth2':
                return [
                    'client_id' => Str::random(20),
                    'client_secret' => Str::random(40),
                    'authorization_endpoint' => fake()->url() . '/oauth/authorize',
                    'token_endpoint' => fake()->url() . '/oauth/token',
                    'user_endpoint' => fake()->url() . '/api/user',
                    'scopes' => ['read', 'profile'],
                ];

            case 'ldap':
                return [
                    'host' => fake()->domainName(),
                    'port' => 389,
                    'base_dn' => 'dc=example,dc=com',
                    'bind_dn' => 'cn=admin,dc=example,dc=com',
                    'bind_password' => 'secret',
                    'user_filter' => '(uid={username})',
                    'attributes' => [
                        'name' => 'cn',
                        'email' => 'mail',
                        'groups' => 'memberOf',
                    ],
                ];

            default:
                return [];
        }
    }

    /**
     * Create SAML2 configuration.
     */
    public function saml2(): static
    {
        return $this->state(fn (array $attributes) => [
            'provider' => 'saml2',
            'configuration' => $this->getConfigurationForProvider('saml2'),
        ]);
    }

    /**
     * Create OIDC configuration.
     */
    public function oidc(): static
    {
        return $this->state(fn (array $attributes) => [
            'provider' => 'oidc',
            'configuration' => $this->getConfigurationForProvider('oidc'),
        ]);
    }

    /**
     * Create OAuth2 configuration.
     */
    public function oauth2(): static
    {
        return $this->state(fn (array $attributes) => [
            'provider' => 'oauth2',
            'configuration' => $this->getConfigurationForProvider('oauth2'),
        ]);
    }

    /**
     * Create LDAP configuration.
     */
    public function ldap(): static
    {
        return $this->state(fn (array $attributes) => [
            'provider' => 'ldap',
            'configuration' => $this->getConfigurationForProvider('ldap'),
        ]);
    }

    /**
     * Create inactive configuration.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Create configuration for specific organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(fn (array $attributes) => [
            'organization_id' => $organization->id,
        ]);
    }
}