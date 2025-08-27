<?php

namespace App\Http\Requests\Profile;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateProfileRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true; // User can always update their own profile
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        $user = $this->user();

        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => [
                'sometimes',
                'email',
                'max:255',
                Rule::unique('users', 'email')->ignore($user->id),
            ],
            'profile' => ['sometimes', 'array'],
            'profile.timezone' => ['sometimes', 'string', 'timezone'],
            'profile.language' => ['sometimes', 'string', 'in:en,es,fr,de,it,pt,nl,ru,ja,zh'],
            'profile.theme' => ['sometimes', 'string', 'in:light,dark,auto'],
            'profile.date_format' => ['sometimes', 'string', 'in:Y-m-d,m/d/Y,d/m/Y,d-m-Y'],
            'profile.time_format' => ['sometimes', 'string', 'in:H:i,h:i A'],
            'profile.department' => ['sometimes', 'string', 'max:100'],
            'profile.job_title' => ['sometimes', 'string', 'max:100'],
            'profile.phone' => ['sometimes', 'string', 'max:20'],
            'profile.bio' => ['sometimes', 'string', 'max:500'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'email.unique' => 'This email address is already in use',
            'profile.timezone.timezone' => 'Please provide a valid timezone',
            'profile.language.in' => 'Please select a supported language',
            'profile.theme.in' => 'Please select a valid theme option',
            'profile.department.max' => 'Department name cannot exceed 100 characters',
            'profile.job_title.max' => 'Job title cannot exceed 100 characters',
            'profile.phone.max' => 'Phone number cannot exceed 20 characters',
            'profile.bio.max' => 'Bio cannot exceed 500 characters',
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
     * Check if email is being changed.
     */
    public function isEmailChanged(): bool
    {
        return $this->has('email') && $this->email !== $this->user()->email;
    }
}