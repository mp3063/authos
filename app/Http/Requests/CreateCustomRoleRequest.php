<?php

namespace App\Http\Requests;

use App\Models\CustomRole;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class CreateCustomRoleRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return auth()->check() && auth()->user()->can('roles.create');
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $organizationId = $this->route('organizationId');

        return [
            'name' => [
                'required',
                'string',
                'max:255',
                'regex:/^[a-zA-Z0-9_\-\s]+$/',
                Rule::unique('custom_roles')->where('organization_id', $organizationId),
            ],
            'display_name' => 'sometimes|string|max:255',
            'description' => 'sometimes|string|max:1000',
            'permissions' => 'required|array|min:1',
            'permissions.*' => [
                'required',
                'string',
                Rule::in(CustomRole::getAvailablePermissions()),
            ],
            'is_active' => 'sometimes|boolean',
        ];
    }

    /**
     * Get custom messages for validation errors
     */
    public function messages(): array
    {
        return [
            'name.required' => 'Role name is required.',
            'name.unique' => 'A role with this name already exists in the organization.',
            'name.regex' => 'Role name can only contain letters, numbers, spaces, hyphens, and underscores.',
            'permissions.required' => 'At least one permission must be assigned to the role.',
            'permissions.min' => 'At least one permission must be assigned to the role.',
            'permissions.*.in' => 'One or more selected permissions are invalid.',
            'description.max' => 'Description cannot exceed 1000 characters.',
        ];
    }

    /**
     * Get custom attribute names for validation errors
     */
    public function attributes(): array
    {
        return [
            'display_name' => 'display name',
        ];
    }

    /**
     * Prepare the data for validation
     */
    protected function prepareForValidation(): void
    {
        // Auto-generate display name if not provided
        if (! $this->has('display_name') && $this->has('name')) {
            $this->merge([
                'display_name' => ucfirst(str_replace(['_', '-'], ' ', $this->name)),
            ]);
        }
    }
}
