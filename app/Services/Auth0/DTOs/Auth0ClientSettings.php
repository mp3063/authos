<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

class Auth0ClientSettings
{
    public function __construct(
        public ?string $description = null,
        public ?string $logoUri = null,
        public ?string $clientSecret = null,
        public bool $isFirstParty = false,
        public bool $oidcConformant = true,
        public ?int $tokenEndpointAuthMethod = null,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            description: $data['description'] ?? null,
            logoUri: $data['logo_uri'] ?? null,
            clientSecret: $data['client_secret'] ?? null,
            isFirstParty: $data['is_first_party'] ?? false,
            oidcConformant: $data['oidc_conformant'] ?? true,
            tokenEndpointAuthMethod: $data['token_endpoint_auth_method'] ?? null,
        );
    }
}
