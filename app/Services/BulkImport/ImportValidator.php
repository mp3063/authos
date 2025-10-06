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
        $errors = [];

        // Validate required fields
        $requiredErrors = $this->validateRequiredFields($record);
        if (! empty($requiredErrors)) {
            $errors = array_merge($errors, $requiredErrors);
            $this->summary['missing_required_fields']++;
        }

        // Validate email format
        if (isset($record['email'])) {
            $emailErrors = $this->validateEmail($record['email']);
            if (! empty($emailErrors)) {
                $errors = array_merge($errors, $emailErrors);
                $this->summary['invalid_emails']++;
            } else {
                // Check for duplicates only if email format is valid
                $duplicateErrors = $this->checkDuplicateEmail($record['email']);
                if (! empty($duplicateErrors)) {
                    $errors = array_merge($errors, $duplicateErrors);
                    $this->summary['duplicate_emails']++;
                }
            }
        }

        // Validate password (if provided and not auto-generating)
        if (! $this->options->autoGeneratePasswords && isset($record['password']) && ! empty($record['password'])) {
            $passwordErrors = $this->validatePassword($record['password']);
            if (! empty($passwordErrors)) {
                $errors = array_merge($errors, $passwordErrors);
                $this->summary['weak_passwords']++;
            }
        }

        // Validate role (if provided)
        if (isset($record['role']) && ! empty($record['role'])) {
            $roleErrors = $this->validateRole($record['role']);
            if (! empty($roleErrors)) {
                $errors = array_merge($errors, $roleErrors);
                $this->summary['invalid_roles']++;
            }
        }

        // Validate name length
        if (isset($record['name']) && strlen($record['name']) > 255) {
            $errors[] = 'Name must not exceed 255 characters';
        }

        // Store result
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
                $query->where(function ($q) {
                    $q->where('organization_id', $this->options->organizationId)
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
