<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;
use Illuminate\Console\Command;

class TestAuth0ConnectionCommand extends Command
{
    protected $signature = 'migrate:auth0-test
                            {--domain= : Auth0 domain (e.g., example.auth0.com)}
                            {--token= : Auth0 Management API token}';

    protected $description = 'Test connection to Auth0 Management API';

    public function handle(): int
    {
        $this->info('Auth0 Connection Test');
        $this->newLine();

        // Get Auth0 credentials
        $domain = $this->option('domain') ?? $this->ask('Auth0 Domain (e.g., example.auth0.com)');
        $token = $this->option('token') ?? $this->secret('Auth0 Management API Token');

        if (! $domain || ! $token) {
            $this->error('Auth0 domain and token are required');

            return self::FAILURE;
        }

        try {
            $this->info('Connecting to Auth0...');
            $client = new Auth0Client($domain, $token);

            // Test basic connection
            if (! $client->testConnection()) {
                $this->error('Failed to connect to Auth0 API');

                return self::FAILURE;
            }

            $this->info('Connection successful!');
            $this->newLine();

            // Test API endpoints
            $this->info('Testing API endpoints:');
            $this->newLine();

            $results = [];

            // Test Users API
            $results[] = $this->testEndpoint('Users API', function () use ($client) {
                $users = iterator_to_array($client->users()->getAll(['per_page' => 1]));

                return count($users);
            });

            // Test Clients API
            $results[] = $this->testEndpoint('Clients API', function () use ($client) {
                $clients = iterator_to_array($client->clients()->getAll(['per_page' => 1]));

                return count($clients);
            });

            // Test Organizations API
            $results[] = $this->testEndpoint('Organizations API', function () use ($client) {
                $orgs = iterator_to_array($client->organizations()->getAll(['per_page' => 1]));

                return count($orgs);
            });

            // Test Roles API
            $results[] = $this->testEndpoint('Roles API', function () use ($client) {
                $roles = iterator_to_array($client->roles()->getAll(['per_page' => 1]));

                return count($roles);
            });

            // Test Connections API
            $results[] = $this->testEndpoint('Connections API', function () use ($client) {
                $connections = iterator_to_array($client->connections()->getAll(['per_page' => 1]));

                return count($connections);
            });

            $this->newLine();

            // Display summary
            $successful = count(array_filter($results));
            $total = count($results);

            if ($successful === $total) {
                $this->info("All {$total} API endpoints are accessible!");
            } else {
                $this->warn("{$successful}/{$total} API endpoints are accessible");
            }

            return $successful === $total ? self::SUCCESS : self::FAILURE;
        } catch (Auth0ApiException $e) {
            $this->error("Auth0 API Error: {$e->getMessage()}");

            return self::FAILURE;
        } catch (\Throwable $e) {
            $this->error("Test failed: {$e->getMessage()}");

            return self::FAILURE;
        }
    }

    /**
     * Test an API endpoint
     */
    private function testEndpoint(string $name, callable $callback): bool
    {
        try {
            $result = $callback();
            $this->line("<fg=green>✓</> {$name}: OK (found {$result} items)");

            return true;
        } catch (\Throwable $e) {
            $this->line("<fg=red>✗</> {$name}: FAILED ({$e->getMessage()})");

            return false;
        }
    }
}
