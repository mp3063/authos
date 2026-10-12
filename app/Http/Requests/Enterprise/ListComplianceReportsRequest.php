<?php

namespace App\Http\Requests\Enterprise;

use App\Models\ComplianceReport;
use Illuminate\Foundation\Http\FormRequest;

class ListComplianceReportsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return ($this->user()?->tokenCan('enterprise.compliance.read') ?? false)
            && $this->user()->can('viewAny', ComplianceReport::class);
    }

    public function rules(): array
    {
        return [
            'report_type' => ['sometimes', 'string', 'in:soc2,iso27001,gdpr'],
            'status' => ['sometimes', 'string', 'in:generating,completed,failed'],
            'from' => ['sometimes', 'date'],
            'to' => ['sometimes', 'date', 'after_or_equal:from'],
            'per_page' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];
    }
}
