<?php

namespace App\Http\Requests\Organization;

use Illuminate\Foundation\Http\FormRequest;

class UpdateOrganizationSettingsRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('organizations.update');
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'settings' => ['required', 'array'],
            'settings.allow_registration' => ['sometimes', 'boolean'],
            'settings.require_email_verification' => ['sometimes', 'boolean'],
            'settings.session_lifetime' => ['sometimes', 'integer', 'min:15', 'max:10080'],
            'settings.password_policy' => ['sometimes', 'array'],
            'settings.password_policy.min_length' => ['sometimes', 'integer', 'min:6', 'max:128'],
            'settings.password_policy.require_uppercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_lowercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_numbers' => ['sometimes', 'boolean'],
            'settings.password_policy.require_symbols' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * Get custom error messages for validation rules.
     */
    public function messages(): array
    {
        return [
            'settings.required' => 'Settings are required.',
            'settings.array' => 'Settings must be an array.',
            'settings.allow_registration.boolean' => 'Allow registration must be true or false.',
            'settings.require_email_verification.boolean' => 'Require email verification must be true or false.',
            'settings.session_lifetime.integer' => 'Session lifetime must be an integer.',
            'settings.session_lifetime.min' => 'Session lifetime must be at least 15 minutes.',
            'settings.session_lifetime.max' => 'Session lifetime cannot exceed 10080 minutes (1 week).',
            'settings.password_policy.array' => 'Password policy must be an array.',
            'settings.password_policy.min_length.integer' => 'Minimum password length must be an integer.',
            'settings.password_policy.min_length.min' => 'Minimum password length must be at least 6 characters.',
            'settings.password_policy.min_length.max' => 'Minimum password length cannot exceed 128 characters.',
            'settings.password_policy.require_uppercase.boolean' => 'Require uppercase must be true or false.',
            'settings.password_policy.require_lowercase.boolean' => 'Require lowercase must be true or false.',
            'settings.password_policy.require_numbers.boolean' => 'Require numbers must be true or false.',
            'settings.password_policy.require_symbols.boolean' => 'Require symbols must be true or false.',
        ];
    }
}
