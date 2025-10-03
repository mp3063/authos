<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\AuditExport>
 */
class AuditExportFactory extends Factory
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
            'user_id' => User::factory(),
            'type' => fake()->randomElement(['csv', 'json', 'excel']),
            'status' => 'pending',
            'filters' => [
                'date_from' => now()->subDays(30)->toDateString(),
                'date_to' => now()->toDateString(),
                'event_types' => ['login', 'logout'],
            ],
            'file_path' => null,
            'started_at' => null,
            'completed_at' => null,
            'error_message' => null,
            'records_count' => null,
        ];
    }

    /**
     * Indicate that the export is processing.
     */
    public function processing(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'processing',
            'started_at' => now(),
        ]);
    }

    /**
     * Indicate that the export is completed.
     */
    public function completed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'completed',
            'file_path' => 'exports/audit-export-'.fake()->uuid().'.'.$attributes['type'],
            'started_at' => now()->subMinutes(5),
            'completed_at' => now(),
            'records_count' => fake()->numberBetween(100, 10000),
        ]);
    }

    /**
     * Indicate that the export has failed.
     */
    public function failed(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'failed',
            'started_at' => now()->subMinutes(2),
            'completed_at' => now(),
            'error_message' => fake()->randomElement([
                'Insufficient disk space',
                'Database connection timeout',
                'Invalid date range specified',
                'Export file generation failed',
            ]),
        ]);
    }
}
