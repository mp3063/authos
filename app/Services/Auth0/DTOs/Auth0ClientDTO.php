<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

class Auth0ClientDTO
{
    /**
     * @param  array<int, string>  $callbacks
     * @param  array<int, string>  $allowedLogoutUrls
     * @param  array<int, string>  $allowedOrigins
     * @param  array<int, string>  $webOrigins
     * @param  array<int, string>  $grantTypes
     * @param  array<string, mixed>  $clientMetadata
     */
    public function __construct(
        public string $clientId,
        public string $name,
        public string $appType,
        public array $callbacks,
        public array $allowedLogoutUrls,
        public array $allowedOrigins,
        public array $webOrigins,
        public array $grantTypes,
        public array $clientMetadata,
        public ?string $description = null,
        public ?string $logoUri = null,
        public ?string $clientSecret = null,
        public bool $isFirstParty = false,
        public bool $oidcConformant = true,
        public ?int $tokenEndpointAuthMethod = null,
    ) {}

    /**
     * Create DTO from Auth0 API response
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            clientId: $data['client_id'] ?? '',
            name: $data['name'] ?? '',
            appType: $data['app_type'] ?? 'regular_web',
            callbacks: $data['callbacks'] ?? [],
            allowedLogoutUrls: $data['allowed_logout_urls'] ?? [],
            allowedOrigins: $data['allowed_origins'] ?? [],
            webOrigins: $data['web_origins'] ?? [],
            grantTypes: $data['grant_types'] ?? [],
            clientMetadata: $data['client_metadata'] ?? [],
            description: $data['description'] ?? null,
            logoUri: $data['logo_uri'] ?? null,
            clientSecret: $data['client_secret'] ?? null,
            isFirstParty: $data['is_first_party'] ?? false,
            oidcConformant: $data['oidc_conformant'] ?? true,
            tokenEndpointAuthMethod: $data['token_endpoint_auth_method'] ?? null,
        );
    }

    /**
     * Check if client is a SPA (Single Page Application)
     */
    public function isSPA(): bool
    {
        return $this->appType === 'spa';
    }

    /**
     * Check if client is a native app
     */
    public function isNative(): bool
    {
        return $this->appType === 'native';
    }

    /**
     * Check if client is a regular web application
     */
    public function isRegularWeb(): bool
    {
        return $this->appType === 'regular_web';
    }

    /**
     * Check if client is a machine-to-machine (M2M) app
     */
    public function isM2M(): bool
    {
        return $this->appType === 'non_interactive';
    }

    /**
     * Check if client supports PKCE
     */
    public function supportsPKCE(): bool
    {
        return $this->isSPA() || $this->isNative();
    }

    /**
     * Check if client requires client secret
     */
    public function requiresClientSecret(): bool
    {
        return $this->isRegularWeb() || $this->isM2M();
    }

    /**
     * Get all redirect URIs (callbacks + logout URLs)
     *
     * @return array<int, string>
     */
    public function getAllRedirectUris(): array
    {
        return array_unique(array_merge($this->callbacks, $this->allowedLogoutUrls));
    }
}
