<?php

namespace Database\Factories;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\OrganizationBranding>
 */
class OrganizationBrandingFactory extends Factory
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
            'logo_path' => null,
            'login_background_path' => null,
            'primary_color' => fake()->randomElement(['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444']),
            'secondary_color' => fake()->randomElement(['#8b5cf6', '#3b82f6', '#6366f1', '#ec4899', '#14b8a6']),
            'custom_css' => null,
            'email_templates' => null,
            'settings' => [
                'show_logo' => true,
                'enable_custom_branding' => true,
            ],
        ];
    }

    /**
     * Indicate that the branding has a logo.
     */
    public function withLogo(): static
    {
        return $this->state(fn (array $attributes) => [
            'logo_path' => 'branding/logos/logo-'.fake()->uuid().'.png',
        ]);
    }

    /**
     * Indicate that the branding has a background image.
     */
    public function withBackground(): static
    {
        return $this->state(fn (array $attributes) => [
            'login_background_path' => 'branding/backgrounds/bg-'.fake()->uuid().'.jpg',
        ]);
    }

    /**
     * Indicate that the branding has custom CSS.
     */
    public function withCustomCss(): static
    {
        return $this->state(fn (array $attributes) => [
            'custom_css' => '.btn-primary { background-color: '.$attributes['primary_color'].'; }',
        ]);
    }

    /**
     * Indicate that the branding has custom email templates.
     */
    public function withEmailTemplates(): static
    {
        return $this->state(fn (array $attributes) => [
            'email_templates' => [
                'welcome' => [
                    'subject' => 'Welcome to {{app_name}}',
                    'body' => 'Hello {{user_name}}, welcome to our platform!',
                ],
                'password_reset' => [
                    'subject' => 'Reset Your Password',
                    'body' => 'Click here to reset your password: {{reset_link}}',
                ],
            ],
        ]);
    }
}
