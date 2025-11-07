<?php

namespace App\Models;

use App\Traits\BelongsToOrganization;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Storage;

class BulkImportJob extends Model
{
    use BelongsToOrganization;
    use HasFactory;

    // Status constants
    public const STATUS_PENDING = 'pending';

    public const STATUS_PROCESSING = 'processing';

    public const STATUS_COMPLETED = 'completed';

    public const STATUS_COMPLETED_WITH_ERRORS = 'completed_with_errors';

    public const STATUS_FAILED = 'failed';

    public const STATUS_CANCELLED = 'cancelled';

    // Type constants
    public const TYPE_IMPORT = 'import';

    public const TYPE_EXPORT = 'export';

    public const TYPE_USERS = 'users';

    protected $fillable = [
        'type',
        'organization_id',
        'created_by',
        'total_records',
        'valid_records',
        'invalid_records',
        'processed_records',
        'failed_records',
        'successful_records',
        'status',
        'options',
        'validation_report',
        'errors',
        'records',
        'filters',
        'columns',
        'export_type',
        'format',
        'file_path',
        'file_format',
        'file_size',
        'error_file_path',
        'started_at',
        'completed_at',
        'processing_time',
    ];

    protected $casts = [
        'options' => 'array',
        'validation_report' => 'array',
        'errors' => 'array',
        'records' => 'array',
        'filters' => 'array',
        'columns' => 'array',
        'started_at' => 'datetime',
        'completed_at' => 'datetime',
    ];

    /**
     * Get the organization that owns this job
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Get the user who created this job
     */
    public function createdBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * Mark the job as processing
     */
    public function markAsProcessing(): void
    {
        $this->update([
            'status' => self::STATUS_PROCESSING,
            'started_at' => now(),
        ]);
    }

    /**
     * Update progress statistics
     */
    public function updateProgress(array $stats): void
    {
        $this->update($stats);
    }

    /**
     * Mark the job as completed
     */
    public function markAsCompleted(): void
    {
        $this->update([
            'status' => self::STATUS_COMPLETED,
            'completed_at' => now(),
            'processing_time' => $this->started_at
                ? now()->diffInSeconds($this->started_at)
                : null,
        ]);
    }

    /**
     * Mark the job as failed
     */
    public function markAsFailed(?string $error = null): void
    {
        $data = [
            'status' => self::STATUS_FAILED,
            'completed_at' => now(),
            'processing_time' => $this->started_at
                ? now()->diffInSeconds($this->started_at)
                : null,
        ];

        if ($error) {
            $errors = $this->errors ?? [];
            $errors[] = [
                'message' => $error,
                'timestamp' => now()->toDateTimeString(),
            ];
            $data['errors'] = $errors;
        }

        $this->update($data);
    }

    /**
     * Mark the job as cancelled
     */
    public function markAsCancelled(): void
    {
        $this->update([
            'status' => self::STATUS_CANCELLED,
            'completed_at' => now(),
            'processing_time' => $this->started_at
                ? now()->diffInSeconds($this->started_at)
                : null,
        ]);
    }

    /**
     * Add validation errors for a specific record
     */
    public function addValidationError(int $row, array $data, array $errors): void
    {
        $currentErrors = $this->errors ?? [];

        $currentErrors[] = [
            'row' => $row,
            'data' => $data,
            'errors' => $errors,
            'timestamp' => now()->toDateTimeString(),
        ];

        $this->update([
            'errors' => $currentErrors,
            'failed_records' => $this->failed_records + 1,
            'processed_records' => $this->processed_records + 1,
        ]);
    }

    /**
     * Store validation report summary
     */
    public function storeValidationReport(array $report): void
    {
        $this->update([
            'validation_report' => $report,
        ]);
    }

    /**
     * Get the progress percentage
     */
    public function getProgressPercentage(): int
    {
        if ($this->total_records === 0) {
            return 0;
        }

        return (int) (($this->processed_records / $this->total_records) * 100);
    }

    /**
     * Check if the job is in progress
     */
    public function isInProgress(): bool
    {
        return in_array($this->status, [self::STATUS_PENDING, self::STATUS_PROCESSING]);
    }

    /**
     * Check if the job is completed
     */
    public function isCompleted(): bool
    {
        return $this->status === self::STATUS_COMPLETED;
    }

    /**
     * Check if the job has failed
     */
    public function hasFailed(): bool
    {
        return $this->status === self::STATUS_FAILED;
    }

    /**
     * Check if the job was cancelled
     */
    public function wasCancelled(): bool
    {
        return $this->status === self::STATUS_CANCELLED;
    }

    /**
     * Get the file URL if it exists
     */
    public function getFileUrl(): ?string
    {
        if (! $this->file_path) {
            return null;
        }

        return Storage::url($this->file_path);
    }

    /**
     * Get the error file URL if it exists
     */
    public function getErrorFileUrl(): ?string
    {
        if (! $this->error_file_path) {
            return null;
        }

        return Storage::url($this->error_file_path);
    }

    /**
     * Delete associated files when job is deleted
     */
    protected static function booted(): void
    {
        static::deleting(function (BulkImportJob $job) {
            if ($job->file_path && Storage::exists($job->file_path)) {
                Storage::delete($job->file_path);
            }

            if ($job->error_file_path && Storage::exists($job->error_file_path)) {
                Storage::delete($job->error_file_path);
            }
        });
    }

    /**
     * Get human-readable status
     */
    public function getStatusLabelAttribute(): string
    {
        return match ($this->status) {
            self::STATUS_PENDING => 'Pending',
            self::STATUS_PROCESSING => 'Processing',
            self::STATUS_COMPLETED => 'Completed',
            self::STATUS_COMPLETED_WITH_ERRORS => 'Completed with Errors',
            self::STATUS_FAILED => 'Failed',
            self::STATUS_CANCELLED => 'Cancelled',
            default => 'Unknown',
        };
    }

    /**
     * Get human-readable type
     */
    public function getTypeLabelAttribute(): string
    {
        return match ($this->type) {
            self::TYPE_IMPORT => 'Import',
            self::TYPE_EXPORT => 'Export',
            default => 'Unknown',
        };
    }

    /**
     * Get formatted file size
     */
    public function getFormattedFileSizeAttribute(): string
    {
        if (! $this->file_size) {
            return 'N/A';
        }

        $units = ['B', 'KB', 'MB', 'GB'];
        $size = $this->file_size;
        $unit = 0;

        while ($size >= 1024 && $unit < count($units) - 1) {
            $size /= 1024;
            $unit++;
        }

        return round($size, 2).' '.$units[$unit];
    }

    /**
     * Scope to filter by status
     */
    public function scopeWithStatus($query, string $status)
    {
        return $query->where('status', $status);
    }

    /**
     * Scope to filter by type
     */
    public function scopeWithType($query, string $type)
    {
        return $query->where('type', $type);
    }

    /**
     * Scope to get recent jobs
     */
    public function scopeRecent($query, int $days = 7)
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }
}
