<?php

namespace App\Services\BulkImport\DTOs;

class ValidationResult
{
    public function __construct(
        public readonly array $validRecords = [],
        public readonly array $invalidRecords = [],
        public readonly array $summary = [],
    ) {}

    public function hasErrors(): bool
    {
        return count($this->invalidRecords) > 0;
    }

    public function getTotalRecords(): int
    {
        return count($this->validRecords) + count($this->invalidRecords);
    }

    public function getValidCount(): int
    {
        return count($this->validRecords);
    }

    public function getInvalidCount(): int
    {
        return count($this->invalidRecords);
    }

    public function toArray(): array
    {
        return [
            'total_records' => $this->getTotalRecords(),
            'valid_records' => $this->getValidCount(),
            'invalid_records' => $this->getInvalidCount(),
            'summary' => $this->summary,
        ];
    }
}
