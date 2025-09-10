<?php

namespace App\Http\Requests\Organization;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateOrganizationRequest extends FormRequest
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
        $organizationId = $this->route('organization') ?? $this->route('id');

        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'slug' => [
                'sometimes',
                'string',
                'max:255',
                'alpha_dash',
                Rule::unique('organizations', 'slug')->whereNull('deleted_at')->ignore($organizationId),
            ],
            'description' => ['sometimes', 'string', 'max:1000'],
            'website' => ['sometimes', 'url', 'max:255'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * Get custom error messages for validation rules.
     */
    public function messages(): array
    {
        return [
            'name.required' => 'Organization name is required.',
            'name.string' => 'Organization name must be a string.',
            'name.max' => 'Organization name cannot exceed 255 characters.',
            'slug.string' => 'Organization slug must be a string.',
            'slug.max' => 'Organization slug cannot exceed 255 characters.',
            'slug.alpha_dash' => 'Organization slug may only contain letters, numbers, dashes, and underscores.',
            'slug.unique' => 'This organization slug is already taken.',
            'description.string' => 'Description must be a string.',
            'description.max' => 'Description cannot exceed 1000 characters.',
            'website.url' => 'Website must be a valid URL.',
            'website.max' => 'Website URL cannot exceed 255 characters.',
            'is_active.boolean' => 'Active status must be true or false.',
        ];
    }
}
