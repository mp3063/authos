<?php

namespace App\Http\Requests\Enterprise;

use App\Models\ScheduledComplianceReport;
use Illuminate\Foundation\Http\FormRequest;

class UpdateScheduledComplianceReportRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->tokenCan('enterprise.compliance.manage') ?? false;
    }

    public function rules(): array
    {
        return [
            'report_type' => ['sometimes', 'string', 'in:soc2,iso27001,gdpr'],
            'frequency' => ['sometimes', 'string', 'in:'.implode(',', ScheduledComplianceReport::FREQUENCIES)],
            'recipients' => ['sometimes', 'array', 'min:1', 'max:50'],
            'recipients.*' => ['required_with:recipients', 'email:rfc'],
            'is_active' => ['sometimes', 'boolean'],
        ];
    }
}
