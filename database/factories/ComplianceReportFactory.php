<?php

namespace Database\Factories;

use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<ComplianceReport>
 */
class ComplianceReportFactory extends Factory
{
    protected $model = ComplianceReport::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $start = fake()->dateTimeBetween('-60 days', '-30 days');
        $end = fake()->dateTimeBetween($start, 'now');

        return [
            'organization_id' => Organization::factory(),
            'generated_by_user_id' => User::factory(),
            'scheduled_report_id' => null,
            'report_type' => fake()->randomElement([
                ComplianceReport::TYPE_SOC2,
                ComplianceReport::TYPE_ISO27001,
                ComplianceReport::TYPE_GDPR,
            ]),
            'status' => ComplianceReport::STATUS_GENERATING,
            'period_start' => $start,
            'period_end' => $end,
            'file_path_pdf' => null,
            'file_path_json' => null,
            'error_message' => null,
            'generated_at' => null,
            'expires_at' => null,
            'summary' => null,
        ];
    }

    public function completed(): static
    {
        return $this->state(fn (array $attributes): array => [
            'status' => ComplianceReport::STATUS_COMPLETED,
            'generated_at' => now(),
            'expires_at' => now()->addDays(180),
            'summary' => [
                'total_users' => fake()->numberBetween(5, 500),
                'mfa_adoption_rate' => fake()->randomFloat(2, 0, 100),
            ],
        ])->afterMaking(function (ComplianceReport $report): void {
            // File paths require the resolved organization_id, so set them after the
            // factory has materialized the parent FKs.
            if ($report->file_path_pdf === null) {
                $uuid = fake()->uuid();
                $datestamp = now()->format('Ymd');
                $report->file_path_pdf = "compliance_reports/{$report->organization_id}/{$report->report_type}_{$datestamp}_{$uuid}.pdf";
                $report->file_path_json = "compliance_reports/{$report->organization_id}/{$report->report_type}_{$datestamp}_{$uuid}.json";
            }
        });
    }

    public function failed(): static
    {
        return $this->state(fn (array $attributes): array => [
            'status' => ComplianceReport::STATUS_FAILED,
            'error_message' => fake()->sentence(),
            'generated_at' => now(),
        ]);
    }

    public function expired(): static
    {
        return $this->completed()->state(fn (array $attributes): array => [
            'expires_at' => now()->subDay(),
        ]);
    }
}
