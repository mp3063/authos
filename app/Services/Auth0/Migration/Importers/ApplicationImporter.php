<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration\Importers;

use App\Models\Application;
use App\Models\Organization;
use App\Services\Auth0\DTOs\Auth0ClientDTO;
use App\Services\Auth0\Migration\ImportResult;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class ApplicationImporter
{
    public function __construct(
        private ?Organization $defaultOrganization = null,
    ) {}

    /**
     * Import applications from Auth0
     *
     * @param  array<int, Auth0ClientDTO>  $auth0Clients
     */
    public function import(array $auth0Clients, bool $dryRun = false): ImportResult
    {
        $result = new ImportResult;

        foreach ($auth0Clients as $auth0Client) {
            try {
                // Skip Auth0 system clients
                if ($this->isSystemClient($auth0Client)) {
                    $result->addSkipped("Skipping system client: {$auth0Client->name}");

                    continue;
                }

                // Check if application already exists
                if (Application::where('name', $auth0Client->name)->exists()) {
                    $result->addSkipped("Application with name {$auth0Client->name} already exists");

                    continue;
                }

                if ($dryRun) {
                    $result->addSuccess($auth0Client, null);

                    continue;
                }

                // Import application
                $application = $this->importApplication($auth0Client);

                $result->addSuccess($auth0Client, $application->id);
            } catch (\Throwable $e) {
                $result->addFailure($auth0Client, $e);
            }
        }

        return $result;
    }

    /**
     * Import a single application
     */
    private function importApplication(Auth0ClientDTO $auth0Client): Application
    {
        return DB::transaction(function () use ($auth0Client) {
            // Create application with required settings
            $settings = [
                'description' => $auth0Client->description ?? "Migrated from Auth0: {$auth0Client->name}",
            ];

            // Create application
            $application = Application::create([
                'name' => $auth0Client->name,
                'organization_id' => $this->getOrganizationId(),
                'redirect_uris' => $this->mapRedirectUris($auth0Client),
                'allowed_origins' => $auth0Client->allowedOrigins,
                'allowed_grant_types' => $this->mapGrantTypes($auth0Client),
                'settings' => $settings,
                'is_active' => true,
            ]);

            // Generate OAuth credentials
            // Note: This will create a new client_id and client_secret
            // You may want to manually update these if you need to preserve the original values
            $application->refresh();

            // Store Auth0 metadata
            $application->update([
                'metadata' => [
                    'auth0_client_id' => $auth0Client->clientId,
                    'auth0_app_type' => $auth0Client->appType,
                    'auth0_grant_types' => $auth0Client->grantTypes,
                    'auth0_client_metadata' => $auth0Client->clientMetadata,
                    'imported_from_auth0' => true,
                    'imported_at' => now()->toIso8601String(),
                ],
            ]);

            return $application;
        });
    }

    /**
     * Map redirect URIs from Auth0 format
     *
     * @return array<int, string>
     */
    private function mapRedirectUris(Auth0ClientDTO $auth0Client): array
    {
        // Combine callbacks and logout URLs
        return array_unique(array_merge(
            $auth0Client->callbacks,
            $auth0Client->allowedLogoutUrls
        ));
    }

    /**
     * Map grant types from Auth0 format to our format
     *
     * @return array<int, string>
     */
    private function mapGrantTypes(Auth0ClientDTO $auth0Client): array
    {
        // If Auth0 client has grant types, use them
        if (! empty($auth0Client->grantTypes)) {
            // Map Auth0 grant types to our grant types
            return array_values(array_unique(array_filter(array_map(function ($grantType) {
                return match ($grantType) {
                    'authorization_code' => 'authorization_code',
                    'implicit' => 'implicit',
                    'refresh_token' => 'refresh_token',
                    'client_credentials' => 'client_credentials',
                    'password' => 'password',
                    'http://auth0.com/oauth/grant-type/password-realm' => 'password',
                    default => null,
                };
            }, $auth0Client->grantTypes))));
        }

        // Default grant types based on app type
        return match ($auth0Client->appType) {
            'regular_web' => ['authorization_code', 'refresh_token'],
            'spa' => ['authorization_code', 'refresh_token'],
            'native' => ['authorization_code', 'refresh_token'],
            'non_interactive' => ['client_credentials'],
            default => ['authorization_code', 'refresh_token'],
        };
    }

    /**
     * Check if client is a system client (should be skipped)
     */
    private function isSystemClient(Auth0ClientDTO $auth0Client): bool
    {
        // Auth0 system clients
        $systemClients = [
            'All Applications',
            'Default App',
            'API Explorer Application',
        ];

        if (in_array($auth0Client->name, $systemClients, true)) {
            return true;
        }

        // Check if client is first-party Auth0 client
        if ($auth0Client->isFirstParty && Str::contains($auth0Client->name, 'Auth0')) {
            return true;
        }

        return false;
    }

    /**
     * Get organization ID for imported applications
     */
    private function getOrganizationId(): ?int
    {
        return $this->defaultOrganization?->id;
    }

    /**
     * Set default organization for imported applications
     */
    public function setDefaultOrganization(Organization $organization): void
    {
        $this->defaultOrganization = $organization;
    }
}
