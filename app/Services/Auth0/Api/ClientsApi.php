<?php

declare(strict_types=1);

namespace App\Services\Auth0\Api;

use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;

class ClientsApi
{
    public function __construct(
        private Auth0Client $client
    ) {}

    /**
     * Get all clients with pagination
     *
     * @param  array<string, mixed>  $query
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getAll(array $query = []): \Generator
    {
        return $this->client->paginate('clients', $query);
    }

    /**
     * Get a single client by ID
     *
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function get(string $clientId): array
    {
        return $this->client->get("clients/{$clientId}");
    }

    /**
     * Get client grants
     *
     * @return array<int, array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function getGrants(string $clientId): array
    {
        return $this->client->get('client-grants', ['client_id' => $clientId]);
    }
}
