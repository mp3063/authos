<?php

namespace Authos\Client;

/**
 * AuthOS PHP Client SDK
 * 
 * Simple PHP client for integrating with AuthOS SSO authentication service
 */
class AuthosClient
{
    private string $authosUrl;
    private int $applicationId;
    private array $allowedDomains;
    private string $callbackUrl;
    private string $logoutUrl;

    public function __construct(array $config)
    {
        $this->authosUrl = rtrim($config['authos_url'], '/');
        $this->applicationId = $config['application_id'];
        $this->allowedDomains = $config['allowed_domains'] ?? [];
        $this->callbackUrl = $config['callback_url'];
        $this->logoutUrl = $config['logout_url'];
    }

    /**
     * Initiate SSO login flow
     */
    public function initiateLogin(string $redirectUri = null): string
    {
        $redirectUri = $redirectUri ?: $this->callbackUrl;
        
        $params = [
            'application_id' => $this->applicationId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'state' => $this->generateState(),
        ];

        $_SESSION['authos_state'] = $params['state'];
        $_SESSION['authos_redirect_uri'] = $redirectUri;

        return $this->authosUrl . '/api/v1/sso/initiate?' . http_build_query($params);
    }

    /**
     * Handle callback and exchange code for tokens
     */
    public function handleCallback(array $params): ?array
    {
        // Validate state parameter
        if (!isset($_SESSION['authos_state']) || 
            !isset($params['state']) || 
            $_SESSION['authos_state'] !== $params['state']) {
            throw new \Exception('Invalid state parameter');
        }

        if (!isset($params['code'])) {
            throw new \Exception('No authorization code received');
        }

        $response = $this->makeRequest('POST', '/api/v1/sso/callback', [
            'code' => $params['code'],
            'application_id' => $this->applicationId,
            'redirect_uri' => $_SESSION['authos_redirect_uri'],
        ]);

        if (!$response['success']) {
            throw new \Exception($response['message'] ?? 'Failed to exchange code for tokens');
        }

        // Store tokens in session
        $_SESSION['authos_access_token'] = $response['data']['access_token'];
        $_SESSION['authos_refresh_token'] = $response['data']['refresh_token'];
        $_SESSION['authos_user'] = $response['data']['user'];

        // Clean up temporary session data
        unset($_SESSION['authos_state'], $_SESSION['authos_redirect_uri']);

        return $response['data'];
    }

    /**
     * Validate current session
     */
    public function validateSession(): ?array
    {
        $accessToken = $_SESSION['authos_access_token'] ?? null;
        
        if (!$accessToken) {
            return null;
        }

        $response = $this->makeRequest('POST', '/api/v1/sso/validate', [
            'token' => $accessToken,
        ]);

        if (!$response['success']) {
            // Try to refresh token
            return $this->refreshSession();
        }

        return $response['data'];
    }

    /**
     * Refresh session token
     */
    public function refreshSession(): ?array
    {
        $refreshToken = $_SESSION['authos_refresh_token'] ?? null;
        
        if (!$refreshToken) {
            return null;
        }

        $response = $this->makeRequest('POST', '/api/v1/sso/refresh', [
            'refresh_token' => $refreshToken,
        ]);

        if (!$response['success']) {
            // Clear invalid tokens
            $this->clearSession();
            return null;
        }

        // Update stored tokens
        $_SESSION['authos_access_token'] = $response['data']['access_token'];
        $_SESSION['authos_refresh_token'] = $response['data']['refresh_token'];

        return $response['data'];
    }

    /**
     * Logout user and synchronize across applications
     */
    public function logout(): array
    {
        $accessToken = $_SESSION['authos_access_token'] ?? null;
        
        if (!$accessToken) {
            return ['success' => true, 'logout_urls' => []];
        }

        $response = $this->makeRequest('POST', '/api/v1/sso/logout', [
            'token' => $accessToken,
        ]);

        // Clear local session regardless of API response
        $this->clearSession();

        return $response;
    }

    /**
     * Get current user information
     */
    public function getUser(): ?array
    {
        return $_SESSION['authos_user'] ?? null;
    }

    /**
     * Check if user is authenticated
     */
    public function isAuthenticated(): bool
    {
        return $this->validateSession() !== null;
    }

    /**
     * Get login URL for redirecting users
     */
    public function getLoginUrl(string $redirectUri = null): string
    {
        return $this->initiateLogin($redirectUri);
    }

    /**
     * Get logout URL
     */
    public function getLogoutUrl(): string
    {
        return $this->logoutUrl;
    }

    /**
     * Middleware function for protecting routes
     */
    public function requireAuth(): void
    {
        if (!$this->isAuthenticated()) {
            $loginUrl = $this->getLoginUrl();
            header('Location: ' . $loginUrl);
            exit;
        }
    }

    private function clearSession(): void
    {
        unset(
            $_SESSION['authos_access_token'],
            $_SESSION['authos_refresh_token'],
            $_SESSION['authos_user'],
            $_SESSION['authos_state'],
            $_SESSION['authos_redirect_uri']
        );
    }

    private function generateState(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function makeRequest(string $method, string $endpoint, array $data = []): array
    {
        $url = $this->authosUrl . $endpoint;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json',
            ],
        ]);

        if (!empty($data)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new \Exception('CURL Error: ' . $error);
        }

        $decoded = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('Invalid JSON response from AuthOS');
        }

        return $decoded;
    }
}

/**
 * Simple usage example:
 * 
 * // Initialize client
 * $authos = new AuthosClient([
 *     'authos_url' => 'https://auth.yourapp.com',
 *     'application_id' => 1,
 *     'callback_url' => 'https://yourapp.com/auth/callback',
 *     'logout_url' => 'https://yourapp.com/logout',
 *     'allowed_domains' => ['yourapp.com'],
 * ]);
 * 
 * // Protect a route
 * $authos->requireAuth();
 * 
 * // Get current user
 * $user = $authos->getUser();
 * 
 * // Login redirect
 * header('Location: ' . $authos->getLoginUrl());
 * 
 * // Handle callback
 * if (isset($_GET['code'])) {
 *     $tokens = $authos->handleCallback($_GET);
 * }
 * 
 * // Logout
 * $result = $authos->logout();
 */