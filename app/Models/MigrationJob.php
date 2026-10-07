<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MigrationJob extends Model
{
    use HasFactory;

    protected $fillable = [
        'organization_id',
        'source',
        'status',
        'config',
        'stats',
        'migrated_data',
        'total_items',
        'error_log',
        'started_at',
        'completed_at',
    ];

    protected function casts(): array
    {
        return [
            'config' => 'array',
            'stats' => 'array',
            'migrated_data' => 'array',
            'error_log' => 'array',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
        ];
    }

    /**
     * Get the organization that owns the migration job.
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Scope to get pending jobs
     */
    public function scopePending($query)
    {
        return $query->where('status', 'pending');
    }

    /**
     * Scope to get running jobs
     */
    public function scopeRunning($query)
    {
        return $query->where('status', 'running');
    }

    /**
     * Scope to get completed jobs
     */
    public function scopeCompleted($query)
    {
        return $query->where('status', 'completed');
    }

    /**
     * Scope to get failed jobs
     */
    public function scopeFailed($query)
    {
        return $query->where('status', 'failed');
    }

    /**
     * Rollback the migration by deleting migrated data
     */
    public function rollback(): void
    {
        // Delete all users and applications that were created during this migration
        if ($this->organization_id) {
            User::where('organization_id', $this->organization_id)->delete();
            Application::where('organization_id', $this->organization_id)->delete();
        }

        // Update status
        $this->update(['status' => 'rolled_back']);
    }

    /**
     * Get a summary of the migration job
     */
    public function getSummary(): string
    {
        $parts = $this->stats ? $this->summarizeStats($this->stats) : [];

        $parts[] = "Status: {$this->status}";

        if ($this->completed_at && $this->started_at) {
            $duration = $this->started_at->diffInSeconds($this->completed_at);
            $parts[] = "Duration: {$duration}s";
        }

        return implode(', ', $parts);
    }

    /**
     * @return list<string>
     */
    private function summarizeStats(array $stats): array
    {
        [$usersMigrated, $usersFailed] = $this->migrationCounts($stats, 'users');
        [$applicationsMigrated] = $this->migrationCounts($stats, 'applications');
        [$rolesMigrated] = $this->migrationCounts($stats, 'roles');

        $candidates = [
            [$usersMigrated, "{$usersMigrated} users migrated"],
            [$usersFailed, "{$usersFailed} failed"],
            [$applicationsMigrated, "{$applicationsMigrated} applications"],
            [$rolesMigrated, "{$rolesMigrated} roles"],
        ];

        $parts = [];
        foreach ($candidates as [$count, $label]) {
            if ($count > 0) {
                $parts[] = $label;
            }
        }

        return $parts;
    }

    /**
     * Reads both the nested format (users => [successful, failed]) and the flat one (users_migrated, users_failed).
     *
     * @return array{0: mixed, 1: mixed}
     */
    private function migrationCounts(array $stats, string $entity): array
    {
        if (isset($stats[$entity]) && is_array($stats[$entity])) {
            return [$stats[$entity]['successful'] ?? 0, $stats[$entity]['failed'] ?? 0];
        }

        if (isset($stats["{$entity}_migrated"])) {
            return [$stats["{$entity}_migrated"], $stats["{$entity}_failed"] ?? 0];
        }

        return [0, 0];
    }

    /**
     * Get error message from error log
     */
    public function getErrorMessageAttribute(): ?string
    {
        if (is_array($this->error_log) && ! empty($this->error_log)) {
            return collect($this->error_log)->map(function ($error) {
                return is_array($error) ? ($error['message'] ?? json_encode($error)) : $error;
            })->implode(', ');
        }

        return null;
    }
}
