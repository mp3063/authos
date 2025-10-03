<?php

namespace App\Http\Requests\Enterprise;

use Illuminate\Foundation\Http\FormRequest;

class ComplianceScheduleRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('organizations.update');
    }

    public function rules(): array
    {
        return [
            'report_type' => ['required', 'in:soc2,iso27001,gdpr'],
            'frequency' => ['required', 'in:daily,weekly,monthly'],
            'email_recipients' => ['required', 'array', 'min:1'],
            'email_recipients.*' => ['email'],
            'start_time' => ['nullable', 'date_format:H:i'],
            'enabled' => ['sometimes', 'boolean'],
        ];
    }

    public function messages(): array
    {
        return [
            'report_type.required' => 'Report type is required',
            'report_type.in' => 'Report type must be soc2, iso27001, or gdpr',
            'frequency.required' => 'Frequency is required',
            'frequency.in' => 'Frequency must be daily, weekly, or monthly',
            'email_recipients.required' => 'At least one email recipient is required',
            'email_recipients.min' => 'At least one email recipient is required',
            'email_recipients.*.email' => 'Each recipient must be a valid email address',
            'start_time.date_format' => 'Start time must be in HH:MM format',
        ];
    }
}
