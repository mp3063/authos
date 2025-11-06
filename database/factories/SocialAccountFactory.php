<?php

namespace Database\Factories;

use App\Models\SocialAccount;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SocialAccount>
 */
class SocialAccountFactory extends Factory
{
    protected $model = SocialAccount::class;

    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'provider' => $this->faker->randomElement(['google', 'github', 'facebook', 'twitter', 'linkedin']),
            'provider_id' => $this->faker->uuid(),
            'name' => $this->faker->name(),
            'email' => $this->faker->email(),
            'avatar' => $this->faker->imageUrl(),
            'provider_token' => bin2hex(random_bytes(32)),
            'provider_refresh_token' => bin2hex(random_bytes(32)),
            'token_expires_at' => now()->addDays(30),
        ];
    }

    public function google(): static
    {
        return $this->state(fn (array $attributes) => [
            'provider' => 'google',
            'provider_id' => 'google-'.$this->faker->randomNumber(9),
        ]);
    }

    public function github(): static
    {
        return $this->state(fn (array $attributes) => [
            'provider' => 'github',
            'provider_id' => 'github-'.$this->faker->randomNumber(9),
        ]);
    }

    public function expired(): static
    {
        return $this->state(fn (array $attributes) => [
            'token_expires_at' => now()->subDays(1),
        ]);
    }
}
