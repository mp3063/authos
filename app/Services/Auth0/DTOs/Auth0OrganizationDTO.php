<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

class Auth0OrganizationDTO
{
    /**
     * @param  array<string, mixed>  $metadata
     * @param  array<string, mixed>  $branding
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $displayName,
        public array $metadata,
        public array $branding,
        public ?string $displayName2 = null,
    ) {}

    /**
     * Create DTO from Auth0 API response
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?? '',
            name: $data['name'] ?? '',
            displayName: $data['display_name'] ?? '',
            metadata: $data['metadata'] ?? [],
            branding: $data['branding'] ?? [],
        );
    }

    /**
     * Get logo URL from branding
     */
    public function getLogoUrl(): ?string
    {
        return $this->branding['logo_url'] ?? null;
    }

    /**
     * Get primary color from branding
     */
    public function getPrimaryColor(): ?string
    {
        return $this->branding['colors']['primary'] ?? null;
    }

    /**
     * Get page background color from branding
     */
    public function getPageBackgroundColor(): ?string
    {
        return $this->branding['colors']['page_background'] ?? null;
    }

    /**
     * Check if organization has custom branding
     */
    public function hasCustomBranding(): bool
    {
        return ! empty($this->branding);
    }
}
