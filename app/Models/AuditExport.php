<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuditExport extends Model
{
    use HasFactory;

    protected $fillable = [
        'organization_id',
        'user_id',
        'type',
        'status',
        'file_path',
        'filters',
        'started_at',
        'completed_at',
        'error_message',
        'records_count',
    ];

    protected function casts(): array
    {
        return [
            'filters' => 'array',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
            'records_count' => 'integer',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Check if export is completed
     */
    public function isCompleted(): bool
    {
        return $this->status === 'completed';
    }

    /**
     * Check if export has failed
     */
    public function hasFailed(): bool
    {
        return $this->status === 'failed';
    }

    /**
     * Check if export is processing
     */
    public function isProcessing(): bool
    {
        return $this->status === 'processing';
    }

    /**
     * Get download URL
     */
    public function getDownloadUrlAttribute(): ?string
    {
        return $this->file_path && $this->isCompleted()
            ? asset('storage/'.$this->file_path)
            : null;
    }

    /**
     * Scope: Completed exports
     */
    public function scopeCompleted($query)
    {
        return $query->where('status', 'completed');
    }

    /**
     * Scope: Pending exports
     */
    public function scopePending($query)
    {
        return $query->where('status', 'pending');
    }

    /**
     * Scope: Failed exports
     */
    public function scopeFailed($query)
    {
        return $query->where('status', 'failed');
    }
}
