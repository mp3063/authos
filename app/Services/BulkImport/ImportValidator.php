<?php

namespace App\Services\BulkImport;

use App\Models\User;
use App\Services\BulkImport\DTOs\ImportOptions;
use App\Services\BulkImport\DTOs\ValidationResult;
use Illuminate\Support\Facades\Validator;
use Spatie\Permission\Models\Role;

class ImportValidator
{
    private array $validRecords = [];

    private array $invalidRecords = [];

    private array $summary = [];

    public function __construct(
        private readonly ImportOptions $options
    ) {}

    /**
     * Validate all records from the parsed file
     */
    public function validate(iterable $records): ValidationResult
    {
        $this->validRecords = [];
        $this->invalidRecords = [];
        $this->summary = [
            'duplicate_emails' => 0,
            'invalid_emails' => 0,
            'missing_required_fields' => 0,
            'invalid_roles' => 0,
            'weak_passwords' => 0,
        ];

        foreach ($records as $rowNumber => $record) {
            $this->validateRecord($rowNumber, $record);
        }

        return new ValidationResult(
            validRecords: $this->validRecords,
            invalidRecords: $this->invalidRecords,
            summary: $this->summary
        );
    }

    /**
     * Validate a single record
     */
    private function validateRecord(int $rowNumber, array $record): void
    {
        $errors = array_merge(
            $this->tally($this->validateRequiredFields($record), 'missing_required_fields'),
            $this->validateEmailField($record),
            $this->validatePasswordField($record),
            $this->validateRoleField($record),
        );

        if (isset($record['name']) && strlen($record['name']) > 255) {
            $errors[] = 'Name must not exceed 255 characters';
        }

        if (empty($errors)) {
            $this->validRecords[] = [
                'row' => $rowNumber,
                'data' => $this->normalizeRecord($record),
            ];
        } else {
            $this->invalidRecords[] = [
                'row' => $rowNumber,
                'data' => $record,
                'errors' => $errors,
            ];
        }
    }

    /**
     * Count a failed check in the summary and pass its errors through
     */
    private function tally(array $errors, string $summaryKey): array
    {
        if (! empty($errors)) {
            $this->summary[$summaryKey]++;
        }

        return $errors;
    }

    private function validateEmailField(array $record): array
    {
        if (! isset($record['email'])) {
            return [];
        }

        $emailErrors = $this->tally($this->validateEmail($record['email']), 'invalid_emails');
        if (! empty($emailErrors)) {
            return $emailErrors;
        }

        return $this->tally($this->checkDuplicateEmail($record['email']), 'duplicate_emails');
    }

    private function validatePasswordField(array $record): array
    {
        if ($this->options->autoGeneratePasswords || empty($record['password'])) {
            return [];
        }

        return $this->tally($this->validatePassword($record['password']), 'weak_passwords');
    }

    private function validateRoleField(array $record): array
    {
        if (empty($record['role'])) {
            return [];
        }

        return $this->tally($this->validateRole($record['role']), 'invalid_roles');
    }

    /**
     * Validate required fields are present
     */
    private function validateRequiredFields(array $record): array
    {
        $errors = [];
        $required = ['email', 'name'];

        // Password is required unless auto-generating or updating existing
        if (! $this->options->autoGeneratePasswords && ! $this->options->updateExisting) {
            $required[] = 'password';
        }

        foreach ($required as $field) {
            if (! isset($record[$field]) || trim($record[$field]) === '') {
                $errors[] = "Field '{$field}' is required";
            }
        }

        return $errors;
    }

    /**
     * Validate email format
     */
    private function validateEmail(string $email): array
    {
        $validator = Validator::make(['email' => $email], [
            'email' => 'required|email:rfc,dns',
        ]);

        if ($validator->fails()) {
            return ['Invalid email format'];
        }

        return [];
    }

    /**
     * Check for duplicate email in database
     */
    private function checkDuplicateEmail(string $email): array
    {
        // If updating existing users is allowed, duplicates are OK
        if ($this->options->updateExisting) {
            return [];
        }

        $exists = User::where('email', $email)
            ->when($this->options->organizationId, function ($query) {
                $query->where('organization_id', $this->options->organizationId);
            })
            ->exists();

        if ($exists) {
            return ['Email already exists in the system'];
        }

        return [];
    }

    /**
     * Validate password strength
     */
    private function validatePassword(string $password): array
    {
        $validator = Validator::make(['password' => $password], [
            'password' => 'required|min:8|max:255',
        ]);

        if ($validator->fails()) {
            return ['Password must be at least 8 characters'];
        }

        return [];
    }

    /**
     * Validate role exists in system
     */
    private function validateRole(string $roleName): array
    {
        $exists = Role::where('name', $roleName)
            ->when($this->options->organizationId, function ($query) {
                $query->where(function ($subQuery) {
                    $subQuery->where('organization_id', $this->options->organizationId)
                        ->orWhereNull('organization_id');
                });
            })
            ->exists();

        if (! $exists) {
            return ["Role '{$roleName}' does not exist"];
        }

        return [];
    }

    /**
     * Normalize record data
     */
    private function normalizeRecord(array $record): array
    {
        return [
            'email' => trim(strtolower($record['email'])),
            'name' => trim($record['name']),
            'password' => $record['password'] ?? null,
            'role' => $record['role'] ?? $this->options->defaultRole,
            'organization_id' => $record['organization_id'] ?? $this->options->organizationId,
            'metadata' => $record['metadata'] ?? null,
        ];
    }
}
