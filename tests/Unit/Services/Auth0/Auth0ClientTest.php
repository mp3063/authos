<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth0;

use App\Services\Auth0\Api\ClientsApi;
use App\Services\Auth0\Api\ConnectionsApi;
use App\Services\Auth0\Api\OrganizationsApi;
use App\Services\Auth0\Api\RolesApi;
use App\Services\Auth0\Api\UsersApi;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Tests\TestCase;

class Auth0ClientTest extends TestCase
{
    private Auth0Client $client;

    private MockHandler $mockHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockHandler = new MockHandler;
        $handlerStack = HandlerStack::create($this->mockHandler);
        $httpClient = new HttpClient(['handler' => $handlerStack]);

        $this->client = new Auth0Client('test.auth0.com', 'test-token');
        $reflection = new \ReflectionClass($this->client);
        $property = $reflection->getProperty('http');
        $property->setAccessible(true);
        $property->setValue($this->client, $httpClient);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_users_api_instance(): void
    {
        $api = $this->client->users();

        $this->assertInstanceOf(UsersApi::class, $api);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_clients_api_instance(): void
    {
        $api = $this->client->clients();

        $this->assertInstanceOf(ClientsApi::class, $api);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_organizations_api_instance(): void
    {
        $api = $this->client->organizations();

        $this->assertInstanceOf(OrganizationsApi::class, $api);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_roles_api_instance(): void
    {
        $api = $this->client->roles();

        $this->assertInstanceOf(RolesApi::class, $api);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_connections_api_instance(): void
    {
        $api = $this->client->connections();

        $this->assertInstanceOf(ConnectionsApi::class, $api);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_makes_successful_get_request(): void
    {
        $this->mockHandler->append(
            new Response(200, [], json_encode(['data' => 'test']))
        );

        $result = $this->client->get('test-endpoint');

        $this->assertEquals(['data' => 'test'], $result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_throws_exception_on_api_error(): void
    {
        $this->mockHandler->append(
            new Response(400, [], json_encode(['error' => 'test_error', 'message' => 'Test error']))
        );

        $this->expectException(Auth0ApiException::class);
        $this->expectExceptionMessage('Test error');

        $this->client->get('test-endpoint');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tests_connection_successfully(): void
    {
        $this->mockHandler->append(
            new Response(200, [], json_encode([]))
        );

        $result = $this->client->testConnection();

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_pagination(): void
    {
        // First page
        $this->mockHandler->append(
            new Response(200, [], json_encode([
                ['id' => 1],
                ['id' => 2],
            ]))
        );

        // Second page (empty)
        $this->mockHandler->append(
            new Response(200, [], json_encode([]))
        );

        $results = [];
        foreach ($this->client->paginate('test-endpoint', [], 2) as $result) {
            $results[] = $result;
        }

        $this->assertCount(2, $results);
        $this->assertEquals(['id' => 1], $results[0]);
        $this->assertEquals(['id' => 2], $results[1]);
    }
}
