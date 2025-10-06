<?php

declare(strict_types=1);

namespace App\Services\Auth0\Api;

use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;

class ConnectionsApi
{
    public function __construct(
        private Auth0Client $client
    ) {}

    /**
     * Get all connections with pagination
     *
     * @param  array<string, mixed>  $query
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getAll(array $query = []): \Generator
    {
        return $this->client->paginate('connections', $query);
    }

    /**
     * Get a single connection by ID
     *
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function get(string $connectionId): array
    {
        return $this->client->get("connections/{$connectionId}");
    }

    /**
     * Get connections by strategy
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getByStrategy(string $strategy): array
    {
        return $this->client->get('connections', ['strategy' => $strategy]);
    }
}
