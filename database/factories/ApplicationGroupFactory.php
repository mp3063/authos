<?php

namespace Database\Factories;

use App\Models\ApplicationGroup;
use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\ApplicationGroup>
 */
class ApplicationGroupFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->unique()->words(2, true).' Group '.fake()->numberBetween(1000, 9999),
            'description' => fake()->sentence(),
            'organization_id' => Organization::factory(),
            'parent_id' => null,
            'is_active' => true,
            'settings' => [
                'inheritance_enabled' => fake()->boolean(80),
                'auto_assign_users' => fake()->boolean(30),
                'default_permissions' => fake()->randomElements(['read', 'write', 'admin'], fake()->numberBetween(1, 2)),
            ],
        ];
    }

    /**
     * Create an inactive group.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Create group for specific organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(fn (array $attributes) => [
            'organization_id' => $organization->id,
        ]);
    }

    /**
     * Create a child group of the specified parent.
     */
    public function childOf(ApplicationGroup $parent): static
    {
        return $this->state(fn (array $attributes) => [
            'parent_id' => $parent->id,
            'organization_id' => $parent->organization_id,
        ]);
    }

    /**
     * Create group with inheritance disabled.
     */
    public function noInheritance(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['inheritance_enabled'] = false;

            return ['settings' => $settings];
        });
    }

    /**
     * Create group with auto-assign enabled.
     */
    public function autoAssign(): static
    {
        return $this->state(function (array $attributes) {
            $settings = $attributes['settings'] ?? [];
            $settings['auto_assign_users'] = true;

            return ['settings' => $settings];
        });
    }
}
