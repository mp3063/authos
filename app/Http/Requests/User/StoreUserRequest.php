<?php

namespace App\Http\Requests\User;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules\Password;

class StoreUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('users.create');
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
                Password::min(8)
                    ->mixedCase()
                    ->numbers()
                    ->symbols()
                    ->uncompromised(),
            ],
            'organization_id' => ['required', 'integer', 'exists:organizations,id'],
            'profile' => ['sometimes', 'array'],
            'profile.timezone' => ['sometimes', 'string', 'timezone'],
            'profile.language' => ['sometimes', 'string', 'in:en,es,fr,de,it,pt,nl,ru,ja,zh'],
            'profile.theme' => ['sometimes', 'string', 'in:light,dark,auto'],
            'profile.department' => ['sometimes', 'string', 'max:100'],
            'profile.job_title' => ['sometimes', 'string', 'max:100'],
            'roles' => ['sometimes', 'array'],
            'roles.*' => ['string', 'exists:roles,name'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'name.required' => 'User name is required',
            'email.required' => 'Email address is required',
            'email.unique' => 'This email address is already registered',
            'password.required' => 'Password is required',
            'organization_id.required' => 'Organization is required',
            'organization_id.exists' => 'Selected organization does not exist',
            'roles.*.exists' => 'One or more selected roles do not exist',
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
     * Get roles with default fallback.
     */
    public function getRoles(): array
    {
        return $this->input('roles', ['user']);
    }
}