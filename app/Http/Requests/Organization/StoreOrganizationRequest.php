<?php

namespace App\Http\Requests\Organization;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Str;

class StoreOrganizationRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('organizations.create');
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'slug' => ['sometimes', 'string', 'max:255', 'unique:organizations,slug', 'regex:/^[a-z0-9-]+$/'],
            'settings' => ['sometimes', 'array'],
            'settings.require_mfa' => ['sometimes', 'boolean'],
            'settings.password_policy' => ['sometimes', 'array'],
            'settings.password_policy.min_length' => ['sometimes', 'integer', 'min:6', 'max:128'],
            'settings.password_policy.require_uppercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_lowercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_numbers' => ['sometimes', 'boolean'],
            'settings.password_policy.require_symbols' => ['sometimes', 'boolean'],
            'settings.session_timeout' => ['sometimes', 'integer', 'min:300', 'max:86400'],
            'settings.allowed_domains' => ['sometimes', 'array'],
            'settings.allowed_domains.*' => ['string', 'regex:/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/'],
            'settings.branding' => ['sometimes', 'array'],
            'settings.branding.logo_url' => ['sometimes', 'string', 'url', 'max:2048'],
            'settings.branding.primary_color' => ['sometimes', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'settings.branding.secondary_color' => ['sometimes', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'name.required' => 'Organization name is required',
            'slug.unique' => 'This organization slug is already taken',
            'slug.regex' => 'Organization slug can only contain lowercase letters, numbers, and hyphens',
            'settings.password_policy.min_length.min' => 'Password minimum length must be at least 6 characters',
            'settings.allowed_domains.*.regex' => 'Please provide valid domain names',
            'settings.branding.primary_color.regex' => 'Primary color must be a valid hex color (e.g., #3B82F6)',
            'settings.branding.secondary_color.regex' => 'Secondary color must be a valid hex color (e.g., #64748B)',
        ];
    }

    /**
     * Prepare the data for validation.
     */
    protected function prepareForValidation()
    {
        // Auto-generate slug if not provided
        if (!$this->has('slug') && $this->has('name')) {
            $this->merge([
                'slug' => $this->generateUniqueSlug($this->name)
            ]);
        }
    }

    /**
     * Handle a failed validation attempt.
     */
    protected function failedValidation(\Illuminate\Contracts\Validation\Validator $validator)
    {
        throw new \Illuminate\Http\Exceptions\HttpResponseException(
            response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422)
        );
    }

    /**
     * Generate a unique slug from name.
     */
    private function generateUniqueSlug(string $name): string
    {
        $baseSlug = Str::slug($name);
        $slug = $baseSlug;
        $counter = 1;

        while (\App\Models\Organization::where('slug', $slug)->exists()) {
            $slug = $baseSlug . '-' . $counter;
            $counter++;
        }

        return $slug;
    }

    /**
     * Get default settings merged with request.
     */
    public function getSettings(): array
    {
        $defaults = [
            'require_mfa' => false,
            'password_policy' => [
                'min_length' => 8,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_symbols' => true,
            ],
            'session_timeout' => 3600, // 1 hour
            'allowed_domains' => [],
            'branding' => [
                'logo_url' => null,
                'primary_color' => '#3B82F6',
                'secondary_color' => '#64748B',
            ],
        ];

        return array_merge($defaults, $this->input('settings', []));
    }
}