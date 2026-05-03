<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\User;
use App\Models\UserConsent;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<UserConsent>
 */
class UserConsentFactory extends Factory
{
    protected $model = UserConsent::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'organization_id' => Organization::factory(),
            'consent_type' => fake()->randomElement([
                UserConsent::TYPE_TERMS,
                UserConsent::TYPE_PRIVACY,
                UserConsent::TYPE_MARKETING,
                UserConsent::TYPE_DATA_PROCESSING,
            ]),
            'terms_version' => 'v1.0',
            'ip_address' => fake()->ipv4(),
            'given_at' => now(),
            'withdrawn_at' => null,
        ];
    }

    public function withdrawn(): static
    {
        return $this->state(fn (array $attributes): array => [
            'withdrawn_at' => now(),
        ]);
    }

    public function ofType(string $type): static
    {
        return $this->state(fn (array $attributes): array => [
            'consent_type' => $type,
        ]);
    }
}
