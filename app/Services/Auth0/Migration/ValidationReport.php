<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

class ValidationReport
{
    /** @var array<string, array<int, array{id: mixed, message: string}>> */
    private array $errors = [];

    /** @var array<string, array<int, array{id: mixed, message: string}>> */
    private array $warnings = [];

    /**
     * Add error
     */
    public function addError(string $category, mixed $id, string $message): void
    {
        $this->errors[$category][] = [
            'id' => $id,
            'message' => $message,
        ];
    }

    /**
     * Add warning
     */
    public function addWarning(string $category, mixed $id, string $message): void
    {
        $this->warnings[$category][] = [
            'id' => $id,
            'message' => $message,
        ];
    }

    /**
     * Check if validation passed
     */
    public function isValid(): bool
    {
        return empty($this->errors);
    }

    /**
     * Check if there are any errors
     */
    public function hasErrors(): bool
    {
        return ! empty($this->errors);
    }

    /**
     * Check if there are any warnings
     */
    public function hasWarnings(): bool
    {
        return ! empty($this->warnings);
    }

    /**
     * Get all errors
     *
     * @return array<string, array<int, array{id: mixed, message: string}>>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Get all warnings
     *
     * @return array<string, array<int, array{id: mixed, message: string}>>
     */
    public function getWarnings(): array
    {
        return $this->warnings;
    }

    /**
     * Get error count
     */
    public function getErrorCount(): int
    {
        return array_sum(array_map('count', $this->errors));
    }

    /**
     * Get warning count
     */
    public function getWarningCount(): int
    {
        return array_sum(array_map('count', $this->warnings));
    }

    /**
     * Get summary
     *
     * @return array{valid: bool, errors: int, warnings: int}
     */
    public function getSummary(): array
    {
        return [
            'valid' => $this->isValid(),
            'errors' => $this->getErrorCount(),
            'warnings' => $this->getWarningCount(),
        ];
    }

    /**
     * Export to JSON
     */
    public function exportToJson(): string
    {
        return json_encode([
            'summary' => $this->getSummary(),
            'errors' => $this->errors,
            'warnings' => $this->warnings,
        ], JSON_PRETTY_PRINT);
    }
}
