<?php

namespace Database\Factories;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\MigrationJob>
 */
class MigrationJobFactory extends Factory
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
            'source' => fake()->randomElement(['auth0', 'okta', 'cognito', 'custom']),
            'status' => 'pending',
            'config' => [
                'tenant_domain' => fake()->domainName(),
                'api_token' => fake()->uuid(),
                'migrate_users' => true,
                'migrate_applications' => fake()->boolean(),
                'migrate_roles' => fake()->boolean(),
            ],
            'stats' => null,
            'error_log' => null,
            'started_at' => null,
            'completed_at' => null,
        ];
    }

    /**
     * Indicate that the migration job is running.
     */
    public function running(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'running',
            'started_at' => now(),
        ]);
    }

    /**
     * Indicate that the migration job is completed.
     */
    public function completed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'completed',
            'started_at' => now()->subHours(2),
            'completed_at' => now(),
            'stats' => [
                'users_migrated' => fake()->numberBetween(10, 1000),
                'applications_migrated' => fake()->numberBetween(1, 50),
                'roles_migrated' => fake()->numberBetween(1, 20),
            ],
        ]);
    }

    /**
     * Indicate that the migration job failed.
     */
    public function failed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'failed',
            'started_at' => now()->subHours(1),
            'completed_at' => now(),
            'error_log' => [
                'error' => 'API authentication failed',
                'code' => 'AUTH_ERROR',
                'timestamp' => now()->toISOString(),
            ],
        ]);
    }
}
