<?php

declare(strict_types=1);

namespace App\Services\Auth0\Api;

use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;

class OrganizationsApi
{
    public function __construct(
        private Auth0Client $client
    ) {}

    /**
     * Get all organizations with pagination
     *
     * @param  array<string, mixed>  $query
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getAll(array $query = []): \Generator
    {
        return $this->client->paginate('organizations', $query);
    }

    /**
     * Get a single organization by ID
     *
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function get(string $organizationId): array
    {
        return $this->client->get("organizations/{$organizationId}");
    }

    /**
     * Get organization members
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getMembers(string $organizationId): array
    {
        $members = [];
        foreach ($this->client->paginate("organizations/{$organizationId}/members") as $member) {
            $members[] = $member;
        }

        return $members;
    }

    /**
     * Get organization roles
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getRoles(string $organizationId): array
    {
        $roles = [];
        foreach ($this->client->paginate("organizations/{$organizationId}/roles") as $role) {
            $roles[] = $role;
        }

        return $roles;
    }

    /**
     * Get organization enabled connections
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getConnections(string $organizationId): array
    {
        return $this->client->get("organizations/{$organizationId}/enabled_connections");
    }
}
