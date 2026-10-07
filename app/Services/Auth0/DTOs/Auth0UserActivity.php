<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

use DateTimeImmutable;
use DateTimeInterface;

class Auth0UserActivity
{
    public function __construct(
        public ?DateTimeInterface $createdAt = null,
        public ?DateTimeInterface $updatedAt = null,
        public ?DateTimeInterface $lastLogin = null,
        public ?int $loginsCount = null,
        public ?bool $blocked = null,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            createdAt: isset($data['created_at']) ? new DateTimeImmutable($data['created_at']) : null,
            updatedAt: isset($data['updated_at']) ? new DateTimeImmutable($data['updated_at']) : null,
            lastLogin: isset($data['last_login']) ? new DateTimeImmutable($data['last_login']) : null,
            loginsCount: $data['logins_count'] ?? null,
            blocked: $data['blocked'] ?? null,
        );
    }
}
