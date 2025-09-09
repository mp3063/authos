<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class LoginRequest extends FormRequest
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
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
            'client_id' => ['sometimes', 'string'],
            'scopes' => ['sometimes', 'array'],
            'scopes.*' => ['string', 'in:openid,profile,email,read,write,admin'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'email.required' => 'An email address is required',
            'email.email' => 'Please provide a valid email address',
            'password.required' => 'A password is required',
            'scopes.array' => 'Scopes must be an array',
            'scopes.*.in' => 'Invalid scope provided',
        ];
    }

    /**
     * Handle a failed validation attempt.
     */
    protected function failedValidation(\Illuminate\Contracts\Validation\Validator $validator)
    {
        throw new \Illuminate\Http\Exceptions\HttpResponseException(
            response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400)
        );
    }

    /**
     * Get scopes with default fallback.
     */
    public function getScopes(): array
    {
        return $this->input('scopes', ['openid']);
    }
}
