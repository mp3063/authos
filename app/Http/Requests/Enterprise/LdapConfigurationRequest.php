<?php

namespace App\Http\Requests\Enterprise;

use Illuminate\Foundation\Http\FormRequest;

class LdapConfigurationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('organizations.update');
    }

    public function rules(): array
    {
        return [
            'host' => ['required', 'string', 'max:255'],
            'port' => ['required', 'integer', 'min:1', 'max:65535'],
            'base_dn' => ['required', 'string', 'max:500'],
            'bind_dn' => ['required_without:username', 'string', 'max:500'],
            'username' => ['required_without:bind_dn', 'string', 'max:500'],
            'bind_password' => ['required_without:password', 'string', 'max:500'],
            'password' => ['required_without:bind_password', 'string', 'max:500'],
            'use_ssl' => ['sometimes', 'boolean'],
            'use_tls' => ['sometimes', 'boolean'],
            'user_filter' => ['nullable', 'string', 'max:500'],
            'user_attribute' => ['nullable', 'string', 'max:100'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    public function messages(): array
    {
        return [
            'host.required' => 'LDAP server host is required',
            'port.required' => 'LDAP server port is required',
            'port.min' => 'Port must be at least 1',
            'port.max' => 'Port cannot exceed 65535',
            'base_dn.required' => 'Base DN is required',
            'bind_dn.required_without' => 'Bind DN (username) is required',
            'username.required_without' => 'Bind DN (username) is required',
            'bind_password.required_without' => 'Bind password is required',
            'password.required_without' => 'Bind password is required',
        ];
    }

    /**
     * Prepare data for validation - normalize bind_dn/bind_password to username/password
     */
    protected function prepareForValidation(): void
    {
        $data = [];

        // Map bind_dn to username if provided
        if ($this->has('bind_dn') && ! $this->has('username')) {
            $data['username'] = $this->input('bind_dn');
        }

        // Map bind_password to password if provided
        if ($this->has('bind_password') && ! $this->has('password')) {
            $data['password'] = $this->input('bind_password');
        }

        if (! empty($data)) {
            $this->merge($data);
        }
    }
}
