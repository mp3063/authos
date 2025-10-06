<?php

namespace Database\Factories;

use App\Models\MigrationJob;
use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<MigrationJob>
 */
class MigrationJobFactory extends Factory
{
    protected $model = MigrationJob::class;

    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'source' => 'auth0',
            'status' => 'pending',
            'config' => [
                'tenant_domain' => 'tenant.auth0.com',
                'api_token' => 'test-api-token',
            ],
            'total_items' => 0,
            'processed_items' => 0,
            'migrated_data' => [],
            'stats' => [],
            'validation_errors' => null,
            'error_message' => null,
            'started_at' => null,
            'completed_at' => null,
        ];
    }

    public function processing(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'processing',
            'started_at' => now(),
        ]);
    }

    public function completed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'completed',
            'started_at' => now()->subMinutes(30),
            'completed_at' => now(),
            'stats' => [
                'users_migrated' => 100,
                'applications_migrated' => 5,
                'duration_seconds' => 1800,
            ],
        ]);
    }

    public function failed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'failed',
            'error_message' => 'Migration failed due to API error',
            'started_at' => now()->subMinutes(10),
            'completed_at' => now(),
        ]);
    }

    public function withItems(int $total): static
    {
        return $this->state(fn (array $attributes) => [
            'total_items' => $total,
        ]);
    }
}
