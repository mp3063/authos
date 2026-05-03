<?php

namespace App\Http\Requests\Enterprise;

use App\Models\ScheduledComplianceReport;
use Illuminate\Foundation\Http\FormRequest;

class ScheduleComplianceReportRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->tokenCan('enterprise.compliance.manage') ?? false;
    }

    public function rules(): array
    {
        return [
            'report_type' => ['required', 'string', 'in:soc2,iso27001,gdpr'],
            'frequency' => ['required', 'string', 'in:'.implode(',', ScheduledComplianceReport::FREQUENCIES)],
            'recipients' => ['required', 'array', 'min:1', 'max:50'],
            'recipients.*' => ['required', 'email:rfc'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }

    public function messages(): array
    {
        return [
            'report_type.in' => 'Report type must be one of: soc2, iso27001, gdpr',
            'frequency.in' => 'Frequency must be one of: '.implode(', ', ScheduledComplianceReport::FREQUENCIES),
            'recipients.max' => 'A schedule can have at most 50 recipients',
            'recipients.*.email' => 'Each recipient must be a valid email address',
        ];
    }
}
