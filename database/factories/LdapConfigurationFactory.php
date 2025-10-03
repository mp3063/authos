<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\LdapConfiguration>
 */
class LdapConfigurationFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->company().' LDAP',
            'host' => fake()->domainName(),
            'port' => fake()->randomElement([389, 636]),
            'base_dn' => 'dc='.fake()->domainWord().',dc=com',
            'username' => 'cn=admin,dc='.fake()->domainWord().',dc=com',
            'password' => fake()->password(),
            'use_ssl' => fake()->boolean(),
            'use_tls' => fake()->boolean(),
            'user_filter' => '(objectClass=person)',
            'user_attribute' => 'uid',
            'is_active' => fake()->boolean(80),
            'sync_settings' => [
                'auto_sync' => fake()->boolean(),
                'sync_interval' => fake()->randomElement([3600, 7200, 86400]),
            ],
        ];
    }
}
