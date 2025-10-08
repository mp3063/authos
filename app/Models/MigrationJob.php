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

    protected $casts = [
        'config' => 'array',
        'stats' => 'array',
        'migrated_data' => 'array',
        'error_log' => 'array',
        'started_at' => 'datetime',
        'completed_at' => 'datetime',
    ];

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
        $parts = [];

        if ($this->stats) {
            // Handle nested format (users => [successful, failed, ...])
            if (isset($this->stats['users']) && is_array($this->stats['users'])) {
                $userStats = $this->stats['users'];
                $successful = $userStats['successful'] ?? 0;
                $failed = $userStats['failed'] ?? 0;

                if ($successful > 0) {
                    $parts[] = "{$successful} users migrated";
                }
                if ($failed > 0) {
                    $parts[] = "{$failed} failed";
                }
            }
            // Handle flat format (users_migrated, users_failed)
            elseif (isset($this->stats['users_migrated'])) {
                $migrated = $this->stats['users_migrated'];
                $failed = $this->stats['users_failed'] ?? 0;

                if ($migrated > 0) {
                    $parts[] = "{$migrated} users migrated";
                }
                if ($failed > 0) {
                    $parts[] = "{$failed} failed";
                }
            }

            // Handle nested format for applications
            if (isset($this->stats['applications']) && is_array($this->stats['applications'])) {
                $appStats = $this->stats['applications'];
                $successful = $appStats['successful'] ?? 0;

                if ($successful > 0) {
                    $parts[] = "{$successful} applications";
                }
            }
            // Handle flat format
            elseif (isset($this->stats['applications_migrated'])) {
                $migrated = $this->stats['applications_migrated'];

                if ($migrated > 0) {
                    $parts[] = "{$migrated} applications";
                }
            }

            // Handle nested format for roles
            if (isset($this->stats['roles']) && is_array($this->stats['roles'])) {
                $roleStats = $this->stats['roles'];
                $successful = $roleStats['successful'] ?? 0;

                if ($successful > 0) {
                    $parts[] = "{$successful} roles";
                }
            }
            // Handle flat format
            elseif (isset($this->stats['roles_migrated'])) {
                $migrated = $this->stats['roles_migrated'];

                if ($migrated > 0) {
                    $parts[] = "{$migrated} roles";
                }
            }
        }

        // Add status
        $parts[] = "Status: {$this->status}";

        // Add duration if completed
        if ($this->completed_at && $this->started_at) {
            $duration = $this->started_at->diffInSeconds($this->completed_at);
            $parts[] = "Duration: {$duration}s";
        }

        return implode(', ', $parts);
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
