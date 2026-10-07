<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

class Auth0UserDTO
{
    /**
     * @param  array<string, mixed>  $appMetadata
     * @param  array<string, mixed>  $userMetadata
     * @param  array<int, array<string, mixed>>  $identities
     */
    public function __construct(
        public string $userId,
        public string $email,
        public string $name,
        public bool $emailVerified,
        public array $appMetadata,
        public array $userMetadata,
        public array $identities,
        public Auth0UserProfile $profile = new Auth0UserProfile,
        public Auth0UserActivity $activity = new Auth0UserActivity,
    ) {}

    /**
     * Create DTO from Auth0 API response
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            userId: $data['user_id'] ?? $data['id'] ?? '',
            email: $data['email'] ?? '',
            name: $data['name'] ?? '',
            emailVerified: $data['email_verified'] ?? false,
            appMetadata: $data['app_metadata'] ?? [],
            userMetadata: $data['user_metadata'] ?? [],
            identities: $data['identities'] ?? [],
            profile: Auth0UserProfile::fromArray($data),
            activity: Auth0UserActivity::fromArray($data),
        );
    }

    /**
     * Check if user has MFA enabled
     */
    public function hasMFA(): bool
    {
        // Check for MFA in app_metadata
        if (isset($this->appMetadata['mfa_enabled']) && $this->appMetadata['mfa_enabled']) {
            return true;
        }

        // Check for MFA enrollments
        if (isset($this->userMetadata['mfa_enrollments']) && ! empty($this->userMetadata['mfa_enrollments'])) {
            return true;
        }

        // Check identities for MFA
        foreach ($this->identities as $identity) {
            if (isset($identity['isSocial']) && ! $identity['isSocial']) {
                // Database connections might have MFA
                if (isset($identity['profileData']['multifactor']) && ! empty($identity['profileData']['multifactor'])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get social connections
     *
     * @return array<int, array{provider: string, userId: string, connection: string, isSocial: bool}>
     */
    public function getSocialConnections(): array
    {
        $social = [];

        foreach ($this->identities as $identity) {
            if (($identity['isSocial'] ?? false) === true) {
                $social[] = [
                    'provider' => $identity['provider'] ?? '',
                    'userId' => $identity['user_id'] ?? '',
                    'connection' => $identity['connection'] ?? '',
                    'isSocial' => true,
                ];
            }
        }

        return $social;
    }

    /**
     * Get primary identity (first database connection or first identity)
     *
     * @return array<string, mixed>|null
     */
    public function getPrimaryIdentity(): ?array
    {
        if (empty($this->identities)) {
            return null;
        }

        // Try to find database connection first
        foreach ($this->identities as $identity) {
            if (($identity['isSocial'] ?? true) === false) {
                return $identity;
            }
        }

        // Return first identity
        return $this->identities[0] ?? null;
    }

    /**
     * Check if user is from database connection (has password)
     */
    public function isDatabaseUser(): bool
    {
        foreach ($this->identities as $identity) {
            if (($identity['isSocial'] ?? true) === false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get organization IDs from metadata
     *
     * @return array<int, string>
     */
    public function getOrganizationIds(): array
    {
        return $this->appMetadata['organizations'] ?? [];
    }

    /**
     * Get role IDs from metadata
     *
     * @return array<int, string>
     */
    public function getRoleIds(): array
    {
        return $this->appMetadata['roles'] ?? [];
    }
}
