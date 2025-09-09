<?php

namespace App\Http\Requests\Application;

use Illuminate\Foundation\Http\FormRequest;

class StoreApplicationRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('applications.create');
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'organization_id' => ['required', 'exists:organizations,id'],
            'name' => ['required', 'string', 'max:255'],
            'description' => ['sometimes', 'string', 'max:1000'],
            'redirect_uris' => ['required', 'array', 'min:1', 'max:10'],
            'redirect_uris.*' => ['required', 'url', 'max:2048'],
            'allowed_origins' => ['sometimes', 'array', 'max:10'],
            'allowed_origins.*' => ['url'],
            'allowed_grant_types' => ['required', 'array'],
            'allowed_grant_types.*' => ['in:authorization_code,client_credentials,refresh_token,password'],
            'scopes' => ['sometimes', 'array'],
            'scopes.*' => ['in:openid,profile,email,read,write,admin'],
            'settings' => ['sometimes', 'array'],
            'settings.token_lifetime' => ['sometimes', 'integer', 'min:300', 'max:86400'], // 5 min to 24 hours
            'settings.refresh_token_lifetime' => ['sometimes', 'integer', 'min:3600', 'max:31536000'], // 1 hour to 1 year
            'settings.require_pkce' => ['sometimes', 'boolean'],
            'settings.auto_approve' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * Get custom error messages for validator.
     */
    public function messages(): array
    {
        return [
            'organization_id.required' => 'Organization is required',
            'organization_id.exists' => 'Selected organization does not exist',
            'name.required' => 'Application name is required',
            'redirect_uris.required' => 'At least one redirect URI is required',
            'redirect_uris.min' => 'At least one redirect URI is required',
            'redirect_uris.max' => 'Maximum 10 redirect URIs allowed',
            'redirect_uris.*.url' => 'Each redirect URI must be a valid URL',
            'allowed_grant_types.required' => 'At least one grant type is required',
            'allowed_grant_types.*.in' => 'Invalid grant type provided',
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
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422)
        );
    }

    /**
     * Get default settings merged with request.
     */
    public function getSettings(): array
    {
        $defaults = [
            'token_lifetime' => 3600,
            'refresh_token_lifetime' => 2592000,
            'require_pkce' => true,
            'auto_approve' => false,
        ];

        return array_merge($defaults, $this->input('settings', []));
    }

    /**
     * Get default scopes.
     */
    public function getScopes(): array
    {
        return $this->input('scopes', ['openid', 'profile', 'email']);
    }
}
