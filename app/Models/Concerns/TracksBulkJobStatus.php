<?php

namespace App\Models\Concerns;

trait TracksBulkJobStatus
{
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
}
