<?php

namespace Database\Factories;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\CustomRole>
 */
class CustomRoleFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $roleBaseName = fake()->randomElement([
            'Team Lead', 'Senior Developer', 'Project Manager', 'QA Lead',
            'DevOps Engineer', 'Business Analyst', 'Product Owner', 'Scrum Master',
        ]);

        // Add unique suffix to avoid constraint violations
        $roleName = $roleBaseName.' '.fake()->unique()->randomNumber(4);

        return [
            'name' => $roleName,
            'display_name' => $roleBaseName, // Keep display name clean
            'description' => fake()->sentence(),
            'organization_id' => Organization::factory(),
            'permissions' => fake()->randomElements([
                'users.view', 'users.create', 'users.edit', 'users.delete',
                'applications.view', 'applications.create', 'applications.edit',
                'reports.view', 'reports.generate', 'settings.view', 'settings.edit',
            ], fake()->numberBetween(3, 8)),
            'is_active' => true,
            'is_system' => false,
            'is_default' => false,
        ];
    }

    /**
     * Indicate that the role is inactive.
     */
    public function inactive(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_active' => false,
        ]);
    }

    /**
     * Create role for specific organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(fn (array $attributes) => [
            'organization_id' => $organization->id,
        ]);
    }

    /**
     * Create role with specific creator.
     */
    public function createdBy(\App\Models\User $user): static
    {
        return $this->state(fn (array $attributes) => [
            'created_by' => $user->id,
            'organization_id' => $user->organization_id,
        ]);
    }

    /**
     * Create role with specific permissions.
     */
    public function withPermissions(array $permissions): static
    {
        return $this->state(fn (array $attributes) => [
            'permissions' => $permissions,
        ]);
    }

    /**
     * Create system role for organization.
     */
    public function system(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_system' => true,
            'name' => 'System Role',
            'display_name' => 'System Role',
            'permissions' => ['users.view', 'profile.edit'],
        ]);
    }

    /**
     * Create admin role.
     */
    public function admin(): static
    {
        return $this->state(fn (array $attributes) => [
            'name' => 'Organization Admin',
            'display_name' => 'Organization Administrator',
            'permissions' => [
                'users.view', 'users.create', 'users.edit', 'users.delete',
                'applications.view', 'applications.create', 'applications.edit', 'applications.delete',
                'reports.view', 'reports.generate', 'reports.export',
                'settings.view', 'settings.edit',
                'roles.view', 'roles.create', 'roles.edit', 'roles.delete',
                'invitations.send', 'invitations.manage',
            ],
        ]);
    }

    /**
     * Create read-only role.
     */
    public function readOnly(): static
    {
        return $this->state(fn (array $attributes) => [
            'name' => 'Read Only',
            'display_name' => 'Read Only User',
            'permissions' => ['users.view', 'applications.view', 'reports.view'],
        ]);
    }

    /**
     * Create a default role.
     */
    public function default(): static
    {
        return $this->state(fn (array $attributes) => [
            'is_default' => true,
        ]);
    }
}
