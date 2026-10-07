<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

class Auth0UserProfile
{
    public function __construct(
        public ?string $picture = null,
        public ?string $nickname = null,
        public ?string $givenName = null,
        public ?string $familyName = null,
        public ?string $phoneNumber = null,
        public ?bool $phoneVerified = null,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            picture: $data['picture'] ?? null,
            nickname: $data['nickname'] ?? null,
            givenName: $data['given_name'] ?? null,
            familyName: $data['family_name'] ?? null,
            phoneNumber: $data['phone_number'] ?? null,
            phoneVerified: $data['phone_verified'] ?? null,
        );
    }
}
