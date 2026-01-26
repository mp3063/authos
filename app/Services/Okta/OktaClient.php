<?php

declare(strict_types=1);

namespace App\Services\Okta;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;

class OktaClient
{
    private PendingRequest $http;

    public function __construct(
        private string $domain,
        private string $apiToken,
    ) {
        $this->http = Http::baseUrl("https://{$this->domain}/api/v1")
            ->withHeaders([
                'Authorization' => "SSWS {$this->apiToken}",
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
            ])
            ->timeout(30);
    }

    /**
     * Get users from Okta.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getUsers(int $limit = 200): array
    {
        $response = $this->http->get('/users', ['limit' => $limit]);
        $response->throw();

        return $response->json();
    }

    /**
     * Get applications from Okta.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getApplications(int $limit = 200): array
    {
        $response = $this->http->get('/apps', ['limit' => $limit]);
        $response->throw();

        return $response->json();
    }

    /**
     * Get groups from Okta.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getGroups(int $limit = 200): array
    {
        $response = $this->http->get('/groups', ['limit' => $limit]);
        $response->throw();

        return $response->json();
    }

    /**
     * Get groups for a specific user.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getUserGroups(string $userId): array
    {
        $response = $this->http->get("/users/{$userId}/groups");
        $response->throw();

        return $response->json();
    }

    /**
     * Test the connection to Okta by fetching organization info.
     *
     * @return array<string, mixed>
     */
    public function testConnection(): array
    {
        $response = $this->http->get('/org');
        $response->throw();

        return $response->json();
    }
}
