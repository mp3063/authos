<?php

namespace Database\Factories;

use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

class BulkImportJobFactory extends Factory
{
    protected $model = BulkImportJob::class;

    public function definition(): array
    {
        return [
            'type' => $this->faker->randomElement(['import', 'export']),
            'organization_id' => Organization::factory(),
            'created_by' => User::factory(),
            'total_records' => $this->faker->numberBetween(10, 1000),
            'valid_records' => $this->faker->numberBetween(8, 900),
            'invalid_records' => $this->faker->numberBetween(0, 100),
            'processed_records' => 0,
            'failed_records' => 0,
            'status' => $this->faker->randomElement(['pending', 'processing', 'completed', 'failed']),
            'options' => [
                'format' => 'csv',
                'update_existing' => false,
                'skip_invalid' => true,
            ],
            'validation_report' => null,
            'errors' => null,
            'file_path' => 'imports/test_'.$this->faker->uuid.'.csv',
            'file_format' => $this->faker->randomElement(['csv', 'json', 'xlsx']),
            'file_size' => $this->faker->numberBetween(1024, 10485760),
            'error_file_path' => null,
            'started_at' => null,
            'completed_at' => null,
            'processing_time' => null,
        ];
    }

    public function pending(): self
    {
        return $this->state(fn (array $attributes) => [
            'status' => BulkImportJob::STATUS_PENDING,
            'processed_records' => 0,
            'started_at' => null,
            'completed_at' => null,
        ]);
    }

    public function processing(): self
    {
        return $this->state(fn (array $attributes) => [
            'status' => BulkImportJob::STATUS_PROCESSING,
            'started_at' => now()->subMinutes(5),
            'completed_at' => null,
        ]);
    }

    public function completed(): self
    {
        return $this->state(function (array $attributes) {
            $total = $attributes['total_records'];
            $invalid = $attributes['invalid_records'];
            $valid = $total - $invalid;

            return [
                'status' => BulkImportJob::STATUS_COMPLETED,
                'valid_records' => $valid,
                'processed_records' => $valid,
                'started_at' => now()->subMinutes(10),
                'completed_at' => now()->subMinutes(2),
                'processing_time' => 480,
            ];
        });
    }

    public function failed(): self
    {
        return $this->state(fn (array $attributes) => [
            'status' => BulkImportJob::STATUS_FAILED,
            'errors' => [
                [
                    'message' => 'Failed to process import',
                    'timestamp' => now()->toDateTimeString(),
                ],
            ],
            'started_at' => now()->subMinutes(10),
            'completed_at' => now()->subMinutes(5),
            'processing_time' => 300,
        ]);
    }

    public function import(): self
    {
        return $this->state(fn (array $attributes) => [
            'type' => BulkImportJob::TYPE_IMPORT,
        ]);
    }

    public function export(): self
    {
        return $this->state(fn (array $attributes) => [
            'type' => BulkImportJob::TYPE_EXPORT,
        ]);
    }
}
