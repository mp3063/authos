<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ExportUsersRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('users.read') || $this->user()->isSuperAdmin();
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'format' => [
                'required',
                'string',
                'in:csv,json,xlsx',
            ],
            'fields' => [
                'sometimes',
                'array',
            ],
            'fields.*' => [
                'string',
                'in:id,email,name,email_verified_at,created_at,updated_at,organization_name,organization_id,roles,is_active,mfa_enabled,provider',
            ],
            'roles' => [
                'sometimes',
                'array',
            ],
            'roles.*' => [
                'string',
                'exists:roles,name',
            ],
            'date_from' => [
                'sometimes',
                'date',
            ],
            'date_to' => [
                'sometimes',
                'date',
                'after_or_equal:date_from',
            ],
            'email_verified_only' => [
                'sometimes',
                'boolean',
            ],
            'active_only' => [
                'sometimes',
                'boolean',
            ],
            'limit' => [
                'sometimes',
                'integer',
                'min:1',
                'max:10000',
            ],
        ];
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'format.required' => 'Export format is required',
            'format.in' => 'Invalid export format. Allowed: csv, json, xlsx',
            'date_to.after_or_equal' => 'End date must be after or equal to start date',
            'limit.max' => 'Export limit cannot exceed 10,000 records',
        ];
    }

    /**
     * Prepare the data for validation.
     */
    protected function prepareForValidation(): void
    {
        // Set organization context from authenticated user
        // Super admins can export from any organization, others are scoped to their org
        if (! $this->user()->isSuperAdmin()) {
            $this->merge([
                'organization_id' => $this->user()->organization_id,
            ]);
        }
    }
}
