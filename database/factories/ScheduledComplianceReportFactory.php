<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ScheduledComplianceReport>
 */
class ScheduledComplianceReportFactory extends Factory
{
    protected $model = ScheduledComplianceReport::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'created_by_user_id' => User::factory(),
            'report_type' => fake()->randomElement(['soc2', 'iso27001', 'gdpr']),
            'frequency' => fake()->randomElement(ScheduledComplianceReport::FREQUENCIES),
            'recipients' => [fake()->safeEmail(), fake()->safeEmail()],
            'next_run_at' => now()->addDay(),
            'last_run_at' => null,
            'is_active' => true,
        ];
    }

    public function due(): static
    {
        return $this->state(fn (array $attributes): array => [
            'next_run_at' => now()->subMinute(),
            'is_active' => true,
        ]);
    }

    public function inactive(): static
    {
        return $this->state(fn (array $attributes): array => [
            'is_active' => false,
        ]);
    }

    public function frequency(string $frequency): static
    {
        return $this->state(fn (array $attributes): array => [
            'frequency' => $frequency,
        ]);
    }
}
