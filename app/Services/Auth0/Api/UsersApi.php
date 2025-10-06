<?php

declare(strict_types=1);

namespace App\Services\Auth0\Api;

use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;

class UsersApi
{
    public function __construct(
        private Auth0Client $client
    ) {}

    /**
     * Get all users with pagination
     *
     * @param  array<string, mixed>  $query
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getAll(array $query = []): \Generator
    {
        return $this->client->paginate('users', $query);
    }

    /**
     * Get a single user by ID
     *
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function get(string $userId): array
    {
        return $this->client->get("users/{$userId}");
    }

    /**
     * Get user's roles
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getRoles(string $userId): array
    {
        return $this->client->get("users/{$userId}/roles");
    }

    /**
     * Get user's organizations
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getOrganizations(string $userId): array
    {
        return $this->client->get("users/{$userId}/organizations");
    }

    /**
     * Get user's permissions
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getPermissions(string $userId): array
    {
        return $this->client->get("users/{$userId}/permissions");
    }

    /**
     * Search users
     *
     * @param  array<string, mixed>  $query
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function search(string $query, array $options = []): array
    {
        return $this->client->get('users', array_merge(['q' => $query], $options));
    }
}
