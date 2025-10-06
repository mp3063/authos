<?php

namespace App\Services\BulkImport\DTOs;

class ExportOptions
{
    public function __construct(
        public readonly string $format,
        public readonly ?int $organizationId = null,
        public readonly ?array $fields = null,
        public readonly ?array $roles = null,
        public readonly ?string $dateFrom = null,
        public readonly ?string $dateTo = null,
        public readonly ?bool $emailVerifiedOnly = null,
        public readonly ?bool $activeOnly = null,
        public readonly ?int $limit = null,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            format: $data['format'] ?? 'csv',
            organizationId: $data['organization_id'] ?? null,
            fields: $data['fields'] ?? null,
            roles: $data['roles'] ?? null,
            dateFrom: $data['date_from'] ?? null,
            dateTo: $data['date_to'] ?? null,
            emailVerifiedOnly: $data['email_verified_only'] ?? null,
            activeOnly: $data['active_only'] ?? null,
            limit: $data['limit'] ?? null,
        );
    }

    public function toArray(): array
    {
        return [
            'format' => $this->format,
            'organization_id' => $this->organizationId,
            'fields' => $this->fields,
            'roles' => $this->roles,
            'date_from' => $this->dateFrom,
            'date_to' => $this->dateTo,
            'email_verified_only' => $this->emailVerifiedOnly,
            'active_only' => $this->activeOnly,
            'limit' => $this->limit,
        ];
    }

    public function getDefaultFields(): array
    {
        return $this->fields ?? [
            'id',
            'email',
            'name',
            'email_verified_at',
            'created_at',
            'organization_name',
            'roles',
            'is_active',
        ];
    }
}
