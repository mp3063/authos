<?php

namespace App\Http\Requests\User;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

class UpdateUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('users.update');
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        $userId = $this->route('user');

        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => [
                'sometimes',
                'email',
                'max:255',
                Rule::unique('users', 'email')->ignore($userId),
            ],
            'password' => [
                'sometimes',
                'string',
                Password::min(8)
                    ->mixedCase()
                    ->numbers()
                    ->symbols()
                    ->uncompromised(),
            ],
            'organization_id' => ['sometimes', 'integer', 'exists:organizations,id'],
            'profile' => ['sometimes', 'array'],
            'profile.timezone' => ['sometimes', 'string', 'timezone'],
            'profile.language' => ['sometimes', 'string', 'in:en,es,fr,de,it,pt,nl,ru,ja,zh'],
            'profile.theme' => ['sometimes', 'string', 'in:light,dark,auto'],
            'profile.department' => ['sometimes', 'string', 'max:100'],
            'profile.job_title' => ['sometimes', 'string', 'max:100'],
            'is_active' => ['sometimes', 'boolean'],
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
}
