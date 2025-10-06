<?php

declare(strict_types=1);

namespace App\Services\Auth0\DTOs;

class Auth0RoleDTO
{
    /**
     * @param  array<int, array{permission_name: string, resource_server_identifier: string}>  $permissions
     */
    public function __construct(
        public string $id,
        public string $name,
        public string $description,
        public array $permissions = [],
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
            description: $data['description'] ?? '',
            permissions: $data['permissions'] ?? [],
        );
    }

    /**
     * Get permission names
     *
     * @return array<int, string>
     */
    public function getPermissionNames(): array
    {
        return array_map(
            fn ($permission) => $permission['permission_name'] ?? '',
            $this->permissions
        );
    }

    /**
     * Check if role has specific permission
     */
    public function hasPermission(string $permissionName): bool
    {
        return in_array($permissionName, $this->getPermissionNames(), true);
    }

    /**
     * Check if role is a system role (e.g., admin, user)
     */
    public function isSystemRole(): bool
    {
        $systemRoles = ['admin', 'user', 'super-admin', 'organization-admin', 'organization-owner'];

        return in_array(strtolower($this->name), $systemRoles, true);
    }
}
