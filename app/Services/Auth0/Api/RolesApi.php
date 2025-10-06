<?php

declare(strict_types=1);

namespace App\Services\Auth0\Api;

use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;

class RolesApi
{
    public function __construct(
        private Auth0Client $client
    ) {}

    /**
     * Get all roles with pagination
     *
     * @param  array<string, mixed>  $query
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getAll(array $query = []): \Generator
    {
        return $this->client->paginate('roles', $query);
    }

    /**
     * Get a single role by ID
     *
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function get(string $roleId): array
    {
        return $this->client->get("roles/{$roleId}");
    }

    /**
     * Get role permissions
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getPermissions(string $roleId): array
    {
        $permissions = [];
        foreach ($this->client->paginate("roles/{$roleId}/permissions") as $permission) {
            $permissions[] = $permission;
        }

        return $permissions;
    }

    /**
     * Get users assigned to a role
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getUsers(string $roleId): array
    {
        $users = [];
        foreach ($this->client->paginate("roles/{$roleId}/users") as $user) {
            $users[] = $user;
        }

        return $users;
    }
}
