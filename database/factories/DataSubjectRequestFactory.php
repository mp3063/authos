<?php

namespace Database\Factories;

use App\Models\DataSubjectRequest;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<DataSubjectRequest>
 */
class DataSubjectRequestFactory extends Factory
{
    protected $model = DataSubjectRequest::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'organization_id' => Organization::factory(),
            'user_id' => User::factory(),
            'request_type' => fake()->randomElement([
                DataSubjectRequest::TYPE_ACCESS,
                DataSubjectRequest::TYPE_RECTIFICATION,
                DataSubjectRequest::TYPE_DELETION,
                DataSubjectRequest::TYPE_PORTABILITY,
                DataSubjectRequest::TYPE_RESTRICTION,
            ]),
            'status' => DataSubjectRequest::STATUS_PENDING,
            'requested_at' => now(),
            'completed_at' => null,
            'notes' => null,
            'handled_by_user_id' => null,
        ];
    }

    public function completed(): static
    {
        return $this->state(fn (array $attributes): array => [
            'status' => DataSubjectRequest::STATUS_COMPLETED,
            'completed_at' => now(),
            'handled_by_user_id' => User::factory(),
        ]);
    }

    public function ofType(string $type): static
    {
        return $this->state(fn (array $attributes): array => [
            'request_type' => $type,
        ]);
    }
}
