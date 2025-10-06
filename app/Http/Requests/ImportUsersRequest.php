<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ImportUsersRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return $this->user()->can('users.create') || $this->user()->isSuperAdmin();
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'file' => [
                'required',
                'file',
                'max:10240', // 10MB
                'mimes:csv,json,xlsx,xls',
            ],
            'format' => [
                'required',
                'string',
                'in:csv,json,xlsx,xls',
            ],
            'update_existing' => [
                'sometimes',
                'boolean',
            ],
            'skip_invalid' => [
                'sometimes',
                'boolean',
            ],
            'send_invitations' => [
                'sometimes',
                'boolean',
            ],
            'auto_generate_passwords' => [
                'sometimes',
                'boolean',
            ],
            'default_role' => [
                'sometimes',
                'nullable',
                'string',
                'exists:roles,name',
            ],
            'batch_size' => [
                'sometimes',
                'integer',
                'min:10',
                'max:500',
            ],
        ];
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'file.required' => 'Please upload a file to import',
            'file.max' => 'File size must not exceed 10MB',
            'file.mimes' => 'File must be in CSV, JSON, or Excel format',
            'format.required' => 'File format is required',
            'format.in' => 'Invalid file format. Allowed: csv, json, xlsx, xls',
            'default_role.exists' => 'The specified default role does not exist',
        ];
    }

    /**
     * Prepare the data for validation.
     */
    protected function prepareForValidation(): void
    {
        // Set organization context from authenticated user
        $this->merge([
            'organization_id' => $this->user()->organization_id,
        ]);

        // Infer format from file extension if not provided
        if (! $this->has('format') && $this->hasFile('file')) {
            $extension = strtolower($this->file('file')->getClientOriginalExtension());
            $this->merge(['format' => $extension]);
        }
    }
}
