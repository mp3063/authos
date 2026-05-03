<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ComplianceReport extends Model
{
    use HasFactory;

    public const STATUS_GENERATING = 'generating';

    public const STATUS_COMPLETED = 'completed';

    public const STATUS_FAILED = 'failed';

    public const TYPE_SOC2 = 'soc2';

    public const TYPE_ISO27001 = 'iso27001';

    public const TYPE_GDPR = 'gdpr';

    protected $fillable = [
        'organization_id',
        'generated_by_user_id',
        'scheduled_report_id',
        'report_type',
        'status',
        'period_start',
        'period_end',
        'file_path_pdf',
        'file_path_json',
        'error_message',
        'generated_at',
        'expires_at',
        'summary',
    ];

    protected function casts(): array
    {
        return [
            'period_start' => 'date',
            'period_end' => 'date',
            'generated_at' => 'datetime',
            'expires_at' => 'datetime',
            'summary' => 'array',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function generatedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'generated_by_user_id');
    }

    public function schedule(): BelongsTo
    {
        return $this->belongsTo(ScheduledComplianceReport::class, 'scheduled_report_id');
    }

    public function isCompleted(): bool
    {
        return $this->status === self::STATUS_COMPLETED;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    public function pdfDownloadUrl(): ?string
    {
        if (! $this->isCompleted() || $this->file_path_pdf === null) {
            return null;
        }

        return url("/api/v1/enterprise/compliance/reports/{$this->id}/download?format=pdf");
    }

    public function jsonDownloadUrl(): ?string
    {
        if (! $this->isCompleted() || $this->file_path_json === null) {
            return null;
        }

        return url("/api/v1/enterprise/compliance/reports/{$this->id}/download?format=json");
    }

    public function scopeCompleted(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_COMPLETED);
    }

    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }
}
