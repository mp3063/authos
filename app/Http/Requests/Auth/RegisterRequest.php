<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

class RegisterRequest extends FormRequest
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
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'unique:users,email', 'max:255'],
            'password' => [
                'required',
                'string',
                'confirmed',
                Password::min(8)
                    ->mixedCase()
                    ->numbers()
                    ->symbols()
                    ->uncompromised(),
            ],
            'organization_slug' => ['sometimes', 'string', 'exists:organizations,slug'],
            'profile' => ['sometimes', 'array'],
            'profile.timezone' => ['sometimes', 'string', 'timezone'],
            'profile.language' => ['sometimes', 'string', 'in:en,es,fr,de,it,pt,nl,ru,ja,zh'],
            'profile.theme' => ['sometimes', 'string', 'in:light,dark,auto'],
            'terms_accepted' => ['required', 'accepted'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'name.required' => 'A name is required',
            'email.required' => 'An email address is required',
            'email.email' => 'Please provide a valid email address',
            'email.unique' => 'This email address is already registered',
            'password.required' => 'A password is required',
            'password.confirmed' => 'Password confirmation does not match',
            'terms_accepted.accepted' => 'You must accept the terms of service',
            'organization_slug.exists' => 'The specified organization does not exist',
        ];
    }

    /**
     * Get custom attributes for validator errors.
     */
    public function attributes(): array
    {
        return [
            'organization_slug' => 'organization',
            'profile.timezone' => 'timezone',
            'profile.language' => 'language',
            'profile.theme' => 'theme',
        ];
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
     * Get validated organization ID from slug.
     */
    public function getOrganizationId(): ?int
    {
        if (! $this->has('organization_slug')) {
            return null;
        }

        $organization = \App\Models\Organization::where('slug', $this->organization_slug)->first();

        return $organization?->id;
    }
}
