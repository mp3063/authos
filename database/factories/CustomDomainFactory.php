<?php

namespace Database\Factories;

use App\Models\CustomDomain;
use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\CustomDomain>
 */
class CustomDomainFactory extends Factory
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
            'domain' => fake()->unique()->domainName(),
            'verification_code' => CustomDomain::generateVerificationCode(),
            'verified_at' => null,
            'is_active' => false,
            'dns_records' => null,
            'ssl_certificate' => null,
            'settings' => [
                'auto_redirect' => false,
                'force_https' => true,
            ],
        ];
    }

    /**
     * Indicate that the domain is verified.
     */
    public function verified(): static
    {
        return $this->state(fn (array $attributes) => [
            'verified_at' => now(),
            'is_active' => true,
            'dns_records' => [
                [
                    'type' => 'TXT',
                    'name' => '_authos-verify',
                    'value' => $attributes['verification_code'],
                    'verified' => true,
                ],
                [
                    'type' => 'CNAME',
                    'name' => '@',
                    'value' => 'authos.app',
                    'verified' => true,
                ],
            ],
        ]);
    }

    /**
     * Indicate that the domain has SSL certificate.
     */
    public function withSsl(): static
    {
        return $this->state(fn (array $attributes) => [
            'ssl_certificate' => [
                'provider' => 'letsencrypt',
                'issued_at' => now()->toDateString(),
                'expires_at' => now()->addMonths(3)->toDateString(),
                'status' => 'active',
                'certificate_id' => fake()->uuid(),
            ],
        ]);
    }

    /**
     * Indicate that the domain is active.
     */
    public function active(): static
    {
        return $this->verified()->state(fn (array $attributes) => [
            'is_active' => true,
        ]);
    }
}
