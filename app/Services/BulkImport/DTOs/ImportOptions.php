<?php

namespace App\Services\BulkImport\DTOs;

class ImportOptions
{
    public function __construct(
        public readonly string $format,
        public readonly bool $updateExisting = false,
        public readonly bool $skipInvalid = true,
        public readonly bool $sendInvitations = false,
        public readonly bool $autoGeneratePasswords = false,
        public readonly ?string $defaultRole = null,
        public readonly ?int $organizationId = null,
        public readonly ?int $batchSize = 100,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            format: $data['format'] ?? 'csv',
            updateExisting: $data['update_existing'] ?? false,
            skipInvalid: $data['skip_invalid'] ?? true,
            sendInvitations: $data['send_invitations'] ?? false,
            autoGeneratePasswords: $data['auto_generate_passwords'] ?? false,
            defaultRole: $data['default_role'] ?? null,
            organizationId: $data['organization_id'] ?? null,
            batchSize: $data['batch_size'] ?? 100,
        );
    }

    public function toArray(): array
    {
        return [
            'format' => $this->format,
            'update_existing' => $this->updateExisting,
            'skip_invalid' => $this->skipInvalid,
            'send_invitations' => $this->sendInvitations,
            'auto_generate_passwords' => $this->autoGeneratePasswords,
            'default_role' => $this->defaultRole,
            'organization_id' => $this->organizationId,
            'batch_size' => $this->batchSize,
        ];
    }
}
