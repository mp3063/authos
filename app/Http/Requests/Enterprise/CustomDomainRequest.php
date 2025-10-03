<?php

namespace App\Http\Requests\Enterprise;

use Illuminate\Foundation\Http\FormRequest;

class CustomDomainRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('organizations.update');
    }

    public function rules(): array
    {
        return [
            'domain' => [
                'required',
                'string',
                'unique:custom_domains,domain',
                'regex:/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/',
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'domain.required' => 'Domain name is required',
            'domain.unique' => 'This domain is already registered',
            'domain.regex' => 'Please enter a valid domain name (e.g., auth.example.com)',
        ];
    }
}
