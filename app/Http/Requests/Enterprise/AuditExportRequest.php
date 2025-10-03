<?php

namespace App\Http\Requests\Enterprise;

use Illuminate\Foundation\Http\FormRequest;

class AuditExportRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('organizations.read');
    }

    public function rules(): array
    {
        return [
            'format' => ['required', 'in:csv,json,excel'],
            'start_date' => ['required', 'date'],
            'end_date' => ['required', 'date', 'after:start_date'],
            'event_types' => ['nullable', 'array'],
            'event_types.*' => ['string'],
            'user_id' => ['nullable', 'exists:users,id'],
            'application_id' => ['nullable', 'exists:applications,id'],
        ];
    }

    public function messages(): array
    {
        return [
            'format.required' => 'Export format is required',
            'format.in' => 'Export format must be csv, json, or excel',
            'start_date.required' => 'Start date is required',
            'end_date.required' => 'End date is required',
            'end_date.after' => 'End date must be after start date',
            'user_id.exists' => 'Selected user does not exist',
            'application_id.exists' => 'Selected application does not exist',
        ];
    }
}
