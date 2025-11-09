<?php

namespace App\Http\Requests\Api;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

class PasswordResetConfirmRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        // Build password validation rules
        $passwordRules = Password::min(8)
            ->mixedCase()
            ->numbers()
            ->symbols();

        // Skip API-based password breach check in testing to prevent timing variance
        // The uncompromised() check makes HTTP calls to haveibeenpwned.com API
        // which adds unpredictable 50-200ms variance that interferes with timing attack tests
        if (! app()->environment('testing')) {
            $passwordRules->uncompromised();
        }

        return [
            'email' => [
                'required',
                'string',
                'email',
                'max:255',
            ],
            'token' => [
                'required',
                'string',
            ],
            'password' => [
                'required',
                'string',
                'confirmed',
                $passwordRules,
            ],
        ];
    }

    /**
     * Get custom error messages
     */
    public function messages(): array
    {
        return [
            'email.required' => 'Email address is required.',
            'email.email' => 'Please provide a valid email address.',
            'token.required' => 'Reset token is required.',
            'password.required' => 'Password is required.',
            'password.confirmed' => 'Password confirmation does not match.',
        ];
    }

    /**
     * Get custom attribute names
     */
    public function attributes(): array
    {
        return [
            'password' => 'password',
            'password_confirmation' => 'password confirmation',
        ];
    }
}
