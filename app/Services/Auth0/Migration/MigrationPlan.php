<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

use App\Services\Auth0\DTOs\Auth0ClientDTO;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\DTOs\Auth0RoleDTO;
use App\Services\Auth0\DTOs\Auth0UserDTO;

class MigrationPlan
{
    /**
     * @param  array<int, Auth0OrganizationDTO>  $organizations
     * @param  array<int, Auth0RoleDTO>  $roles
     * @param  array<int, Auth0ClientDTO>  $applications
     * @param  array<int, Auth0UserDTO>  $users
     * @param  array<int, array<string, mixed>>  $connections
     */
    public function __construct(
        public array $organizations = [],
        public array $roles = [],
        public array $applications = [],
        public array $users = [],
        public array $connections = [],
    ) {}

    /**
     * Get total items to migrate
     */
    public function getTotalItems(): int
    {
        return count($this->organizations)
            + count($this->roles)
            + count($this->applications)
            + count($this->users);
    }

    /**
     * Get summary
     *
     * @return array{organizations: int, roles: int, applications: int, users: int, connections: int, total: int}
     */
    public function getSummary(): array
    {
        return [
            'organizations' => count($this->organizations),
            'roles' => count($this->roles),
            'applications' => count($this->applications),
            'users' => count($this->users),
            'connections' => count($this->connections),
            'total' => $this->getTotalItems(),
        ];
    }

    /**
     * Export to JSON
     */
    public function exportToJson(): string
    {
        return json_encode([
            'organizations' => array_map(fn ($org) => [
                'id' => $org->id,
                'name' => $org->name,
                'display_name' => $org->displayName,
                'metadata' => $org->metadata,
                'branding' => $org->branding,
            ], $this->organizations),
            'roles' => array_map(fn ($role) => [
                'id' => $role->id,
                'name' => $role->name,
                'description' => $role->description,
                'permissions' => $role->permissions,
            ], $this->roles),
            'applications' => array_map(fn ($app) => [
                'client_id' => $app->clientId,
                'name' => $app->name,
                'app_type' => $app->appType,
                'callbacks' => $app->callbacks,
                'allowed_logout_urls' => $app->allowedLogoutUrls,
                'grant_types' => $app->grantTypes,
            ], $this->applications),
            'users' => array_map(fn ($user) => [
                'user_id' => $user->userId,
                'email' => $user->email,
                'name' => $user->name,
                'email_verified' => $user->emailVerified,
                'identities' => $user->identities,
                'has_mfa' => $user->hasMFA(),
                'is_database_user' => $user->isDatabaseUser(),
            ], $this->users),
            'connections' => $this->connections,
            'summary' => $this->getSummary(),
        ], JSON_PRETTY_PRINT);
    }

    /**
     * Check if migration plan is empty
     */
    public function isEmpty(): bool
    {
        return $this->getTotalItems() === 0;
    }

    /**
     * Add organization
     */
    public function addOrganization(Auth0OrganizationDTO $organization): void
    {
        $this->organizations[] = $organization;
    }

    /**
     * Add role
     */
    public function addRole(Auth0RoleDTO $role): void
    {
        $this->roles[] = $role;
    }

    /**
     * Add application
     */
    public function addApplication(Auth0ClientDTO $application): void
    {
        $this->applications[] = $application;
    }

    /**
     * Add user
     */
    public function addUser(Auth0UserDTO $user): void
    {
        $this->users[] = $user;
    }

    /**
     * Add connection
     *
     * @param  array<string, mixed>  $connection
     */
    public function addConnection(array $connection): void
    {
        $this->connections[] = $connection;
    }
}
