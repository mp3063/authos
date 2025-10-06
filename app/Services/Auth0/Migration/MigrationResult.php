<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

class MigrationResult
{
    public function __construct(
        public ImportResult $organizations,
        public ImportResult $roles,
        public ImportResult $applications,
        public ImportResult $users,
        public ?\DateTimeInterface $startedAt = null,
        public ?\DateTimeInterface $completedAt = null,
        public bool $dryRun = false,
    ) {
        $this->startedAt = $this->startedAt ?? new \DateTimeImmutable;
    }

    /**
     * Mark migration as completed
     */
    public function markCompleted(): void
    {
        $this->completedAt = new \DateTimeImmutable;
    }

    /**
     * Get success count across all imports
     */
    public function getSuccessCount(): int
    {
        return $this->organizations->getSuccessCount()
            + $this->roles->getSuccessCount()
            + $this->applications->getSuccessCount()
            + $this->users->getSuccessCount();
    }

    /**
     * Get failure count across all imports
     */
    public function getFailureCount(): int
    {
        return $this->organizations->getFailureCount()
            + $this->roles->getFailureCount()
            + $this->applications->getFailureCount()
            + $this->users->getFailureCount();
    }

    /**
     * Get skipped count across all imports
     */
    public function getSkippedCount(): int
    {
        return $this->organizations->getSkippedCount()
            + $this->roles->getSkippedCount()
            + $this->applications->getSkippedCount()
            + $this->users->getSkippedCount();
    }

    /**
     * Get total count across all imports
     */
    public function getTotalCount(): int
    {
        return $this->getSuccessCount() + $this->getFailureCount() + $this->getSkippedCount();
    }

    /**
     * Check if migration was successful
     */
    public function isSuccessful(): bool
    {
        return $this->getFailureCount() === 0;
    }

    /**
     * Check if migration has failures
     */
    public function hasFailures(): bool
    {
        return $this->getFailureCount() > 0;
    }

    /**
     * Get success rate
     */
    public function getSuccessRate(): float
    {
        $total = $this->getTotalCount();

        return $total > 0 ? ($this->getSuccessCount() / $total) * 100 : 0.0;
    }

    /**
     * Get duration in seconds
     */
    public function getDuration(): ?float
    {
        if (! $this->completedAt || ! $this->startedAt) {
            return null;
        }

        return $this->completedAt->getTimestamp() - $this->startedAt->getTimestamp();
    }

    /**
     * Get comprehensive report
     *
     * @return array{
     *     started_at: string|null,
     *     completed_at: string|null,
     *     duration_seconds: float|null,
     *     dry_run: bool,
     *     total: int,
     *     successful: int,
     *     failed: int,
     *     skipped: int,
     *     success_rate: float,
     *     organizations: array{total: int, successful: int, failed: int, skipped: int, success_rate: float},
     *     roles: array{total: int, successful: int, failed: int, skipped: int, success_rate: float},
     *     applications: array{total: int, successful: int, failed: int, skipped: int, success_rate: float},
     *     users: array{total: int, successful: int, failed: int, skipped: int, success_rate: float}
     * }
     */
    public function getReport(): array
    {
        return [
            'started_at' => $this->startedAt?->format('Y-m-d H:i:s'),
            'completed_at' => $this->completedAt?->format('Y-m-d H:i:s'),
            'duration_seconds' => $this->getDuration(),
            'dry_run' => $this->dryRun,
            'total' => $this->getTotalCount(),
            'successful' => $this->getSuccessCount(),
            'failed' => $this->getFailureCount(),
            'skipped' => $this->getSkippedCount(),
            'success_rate' => $this->getSuccessRate(),
            'organizations' => $this->organizations->getSummary(),
            'roles' => $this->roles->getSummary(),
            'applications' => $this->applications->getSummary(),
            'users' => $this->users->getSummary(),
        ];
    }

    /**
     * Get all error messages
     *
     * @return array{organizations: array<int, string>, roles: array<int, string>, applications: array<int, string>, users: array<int, string>}
     */
    public function getAllErrors(): array
    {
        return [
            'organizations' => $this->organizations->getErrorMessages(),
            'roles' => $this->roles->getErrorMessages(),
            'applications' => $this->applications->getErrorMessages(),
            'users' => $this->users->getErrorMessages(),
        ];
    }

    /**
     * Export report to JSON
     */
    public function exportToJson(): string
    {
        return json_encode($this->getReport(), JSON_PRETTY_PRINT);
    }
}
