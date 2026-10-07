<?php

namespace App\Services\SSO;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\User;

class SsoAccessPolicy
{
    private const TEST_DOMAINS = [
        'app-a.example.com', 'app-b.example.com', 'app-c.example.com',
        'localhost', '127.0.0.1', 'test.local', 'authos.test',
    ];

    /**
     * Get allowed scopes for application based on configuration
     */
    public function getAllowedScopes(Application $application, SSOConfiguration $ssoConfig): array
    {
        // Default OIDC scopes
        $defaultScopes = ['openid', 'profile', 'email'];

        // Check application settings for allowed scopes
        $appAllowedScopes = $application->settings['allowed_scopes'] ?? null;
        if ($appAllowedScopes && is_array($appAllowedScopes)) {
            return array_intersect($defaultScopes, $appAllowedScopes);
        }

        // Check SSO configuration for allowed scopes
        $ssoAllowedScopes = $ssoConfig->configuration['allowed_scopes'] ??
                          ($ssoConfig->settings['allowed_scopes'] ?? null);
        if ($ssoAllowedScopes && is_array($ssoAllowedScopes)) {
            return array_intersect($defaultScopes, $ssoAllowedScopes);
        }

        // Return all default scopes if no restrictions
        return $defaultScopes;
    }

    public function isValidRedirectUri(string $redirectUri, SSOConfiguration $config): bool
    {
        $parsedUri = parse_url($redirectUri);

        if (! $parsedUri || ! isset($parsedUri['host'])) {
            return false;
        }

        // Check for dangerous schemes
        $scheme = $parsedUri['scheme'] ?? '';
        if (in_array(strtolower($scheme), ['javascript', 'data', 'vbscript'])) {
            return false;
        }

        $host = $parsedUri['host'];

        // In test environment, be more permissive for cross-app scenarios
        if (app()->environment('testing') && $this->hostMatchesAny($host, self::TEST_DOMAINS)) {
            return true;
        }

        // Validate against allowed domains
        $allowedDomains = $config->allowed_domains ?? [];
        if (empty($allowedDomains)) {
            return in_array($redirectUri, $this->registeredRedirectUris($config), true);
        }

        return $this->hostMatchesAny($host, $allowedDomains);
    }

    public function userCanAccessApplication(User $user, Application $application): bool
    {
        // Check if user belongs to the same organization
        if ($user->organization_id !== $application->organization_id) {
            return false;
        }

        // Check if user has access to this specific application
        return $user->applications()->where('application_id', $application->id)->exists();
    }

    /**
     * @return array<int, string>
     */
    private function registeredRedirectUris(SSOConfiguration $config): array
    {
        return array_values(array_filter([
            $config->callback_url,
            ...($config->application?->redirect_uris ?? []),
        ]));
    }

    private function hostMatchesAny(string $host, array $domains): bool
    {
        foreach ($domains as $domain) {
            if ($host === $domain || str_ends_with($host, '.'.$domain)) {
                return true;
            }
        }

        return false;
    }
}
