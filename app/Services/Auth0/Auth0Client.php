<?php

declare(strict_types=1);

namespace App\Services\Auth0;

use App\Services\Auth0\Api\ClientsApi;
use App\Services\Auth0\Api\ConnectionsApi;
use App\Services\Auth0\Api\OrganizationsApi;
use App\Services\Auth0\Api\RolesApi;
use App\Services\Auth0\Api\UsersApi;
use App\Services\Auth0\Exceptions\Auth0ApiException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

class Auth0Client
{
    private string $domain;

    private string $token;

    public function __construct(string $domain, string $token)
    {
        $this->domain = rtrim($domain, '/');
        $this->token = $token;
    }

    public function users(): UsersApi
    {
        return new UsersApi($this);
    }

    public function clients(): ClientsApi
    {
        return new ClientsApi($this);
    }

    public function organizations(): OrganizationsApi
    {
        return new OrganizationsApi($this);
    }

    public function roles(): RolesApi
    {
        return new RolesApi($this);
    }

    public function connections(): ConnectionsApi
    {
        return new ConnectionsApi($this);
    }

    /**
     * Make a GET request to the Auth0 API
     *
     * @param  array<string, mixed>  $query
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function get(string $endpoint, array $query = []): array
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => "Bearer {$this->token}",
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ])->timeout(60)->get("https://{$this->domain}/api/v2/{$endpoint}", $query);

            return $this->handleResponse($response);
        } catch (\Exception $e) {
            throw new Auth0ApiException("Auth0 API request failed: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * Make a POST request to the Auth0 API
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    public function post(string $endpoint, array $data = []): array
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => "Bearer {$this->token}",
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ])->timeout(60)->post("https://{$this->domain}/api/v2/{$endpoint}", $data);

            return $this->handleResponse($response);
        } catch (\Exception $e) {
            throw new Auth0ApiException("Auth0 API request failed: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * Test the connection to Auth0 API
     *
     * @throws Auth0ApiException
     */
    public function testConnection(): bool
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => "Bearer {$this->token}",
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ])->timeout(60)->get("https://{$this->domain}/api/v2/users", ['per_page' => 1]);

            return $response->successful();
        } catch (\Exception $e) {
            throw new Auth0ApiException("Auth0 connection test failed: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * Get paginated results from Auth0 API
     *
     * @param  array<string, mixed>  $query
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    public function paginate(string $endpoint, array $query = [], int $perPage = 100): \Generator
    {
        $page = 0;
        $query['per_page'] = $perPage;

        do {
            $query['page'] = $page;
            $results = $this->get($endpoint, $query);

            if (empty($results)) {
                break;
            }

            foreach ($results as $result) {
                yield $result;
            }

            $page++;

            // Auth0 returns less than per_page when we've reached the end
            $hasMore = count($results) === $perPage;
        } while ($hasMore);
    }

    /**
     * Handle API response
     *
     * @return array<string, mixed>
     *
     * @throws Auth0ApiException
     */
    private function handleResponse(Response $response): array
    {
        $statusCode = $response->status();

        if ($statusCode >= 400) {
            $data = $response->json() ?? [];
            $message = $data['message'] ?? $data['error_description'] ?? 'Unknown error';
            $errorCode = $data['error'] ?? $data['errorCode'] ?? 'unknown_error';

            throw new Auth0ApiException(
                "Auth0 API error ({$errorCode}): {$message}",
                $statusCode
            );
        }

        return $response->json() ?? [];
    }
}
