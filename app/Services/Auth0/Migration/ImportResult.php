<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

class ImportResult
{
    /** @var array<int, array{item: mixed, id: mixed}> */
    private array $successfulItems = [];

    /** @var array<int, array{item: mixed, error: \Throwable}> */
    private array $failedItems = [];

    /** @var array<int, string> */
    private array $skippedItems = [];

    /**
     * Public counters for backward compatibility with migration jobs
     * These are updated whenever items are added
     */
    public int $total = 0;

    public int $successful = 0;

    public int $failed = 0;

    public int $skipped = 0;

    /**
     * Add successful import
     */
    public function addSuccess(mixed $item, mixed $id = null): void
    {
        $this->successfulItems[] = [
            'item' => $item,
            'id' => $id,
        ];
        $this->successful++;
        $this->total++;
    }

    /**
     * Add failed import
     */
    public function addFailure(mixed $item, \Throwable $error): void
    {
        $this->failedItems[] = [
            'item' => $item,
            'error' => $error,
        ];
        $this->failed++;
        $this->total++;
    }

    /**
     * Add skipped import
     */
    public function addSkipped(string $reason): void
    {
        $this->skippedItems[] = $reason;
        $this->skipped++;
        $this->total++;
    }

    /**
     * Get successful imports
     *
     * @return array<int, array{item: mixed, id: mixed}>
     */
    public function getSuccessful(): array
    {
        return $this->successfulItems;
    }

    /**
     * Get failed imports
     *
     * @return array<int, array{item: mixed, error: \Throwable}>
     */
    public function getFailed(): array
    {
        return $this->failedItems;
    }

    /**
     * Get skipped imports
     *
     * @return array<int, string>
     */
    public function getSkipped(): array
    {
        return $this->skippedItems;
    }

    /**
     * Get IDs of successfully imported items
     *
     * @return array<int, mixed>
     */
    public function getSuccessfulIds(): array
    {
        return array_map(fn ($item) => $item['id'], $this->successfulItems);
    }

    /**
     * Get success count
     */
    public function getSuccessCount(): int
    {
        return count($this->successfulItems);
    }

    /**
     * Get failure count
     */
    public function getFailureCount(): int
    {
        return count($this->failedItems);
    }

    /**
     * Get skipped count
     */
    public function getSkippedCount(): int
    {
        return count($this->skippedItems);
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
        return array_map(fn ($failed) => $failed['error']->getMessage(), $this->failedItems);
    }

    /**
     * Merge another ImportResult into this one
     */
    public function merge(ImportResult $other): void
    {
        $this->successfulItems = array_merge($this->successfulItems, $other->successfulItems);
        $this->failedItems = array_merge($this->failedItems, $other->failedItems);
        $this->skippedItems = array_merge($this->skippedItems, $other->skippedItems);

        // Update counters
        $this->successful += $other->successful;
        $this->failed += $other->failed;
        $this->skipped += $other->skipped;
        $this->total += $other->total;
    }
}
