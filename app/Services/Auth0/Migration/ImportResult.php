<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

class ImportResult
{
    /** @var array<int, array{item: mixed, id: mixed}> */
    private array $successful = [];

    /** @var array<int, array{item: mixed, error: \Throwable}> */
    private array $failed = [];

    /** @var array<int, string> */
    private array $skipped = [];

    /**
     * Add successful import
     */
    public function addSuccess(mixed $item, mixed $id = null): void
    {
        $this->successful[] = [
            'item' => $item,
            'id' => $id,
        ];
    }

    /**
     * Add failed import
     */
    public function addFailure(mixed $item, \Throwable $error): void
    {
        $this->failed[] = [
            'item' => $item,
            'error' => $error,
        ];
    }

    /**
     * Add skipped import
     */
    public function addSkipped(string $reason): void
    {
        $this->skipped[] = $reason;
    }

    /**
     * Get successful imports
     *
     * @return array<int, array{item: mixed, id: mixed}>
     */
    public function getSuccessful(): array
    {
        return $this->successful;
    }

    /**
     * Get failed imports
     *
     * @return array<int, array{item: mixed, error: \Throwable}>
     */
    public function getFailed(): array
    {
        return $this->failed;
    }

    /**
     * Get skipped imports
     *
     * @return array<int, string>
     */
    public function getSkipped(): array
    {
        return $this->skipped;
    }

    /**
     * Get IDs of successfully imported items
     *
     * @return array<int, mixed>
     */
    public function getSuccessfulIds(): array
    {
        return array_map(fn ($item) => $item['id'], $this->successful);
    }

    /**
     * Get success count
     */
    public function getSuccessCount(): int
    {
        return count($this->successful);
    }

    /**
     * Get failure count
     */
    public function getFailureCount(): int
    {
        return count($this->failed);
    }

    /**
     * Get skipped count
     */
    public function getSkippedCount(): int
    {
        return count($this->skipped);
    }

    /**
     * Get total count
     */
    public function getTotalCount(): int
    {
        return $this->getSuccessCount() + $this->getFailureCount() + $this->getSkippedCount();
    }

    /**
     * Check if all imports were successful
     */
    public function isSuccessful(): bool
    {
        return $this->getFailureCount() === 0;
    }

    /**
     * Check if any imports failed
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
     * Get summary
     *
     * @return array{total: int, successful: int, failed: int, skipped: int, success_rate: float}
     */
    public function getSummary(): array
    {
        return [
            'total' => $this->getTotalCount(),
            'successful' => $this->getSuccessCount(),
            'failed' => $this->getFailureCount(),
            'skipped' => $this->getSkippedCount(),
            'success_rate' => $this->getSuccessRate(),
        ];
    }

    /**
     * Get error messages
     *
     * @return array<int, string>
     */
    public function getErrorMessages(): array
    {
        return array_map(fn ($failed) => $failed['error']->getMessage(), $this->failed);
    }

    /**
     * Merge another ImportResult into this one
     */
    public function merge(ImportResult $other): void
    {
        $this->successful = array_merge($this->successful, $other->successful);
        $this->failed = array_merge($this->failed, $other->failed);
        $this->skipped = array_merge($this->skipped, $other->skipped);
    }
}
