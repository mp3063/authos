<?php

namespace App\Services;

use App\Models\Application;
use App\Models\SSOSession;
use App\Models\SSOConfiguration;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Exception;

class SSOService
{
    /**
     * Initiate SSO flow for an application
     */
    public function initiateSSO(
        int $applicationId, 
        string $redirectUri, 
        User $user,
        string $ipAddress,
        string $userAgent
    ): array {
        $application = Application::with('ssoConfiguration')->findOrFail($applicationId);
        
        if (!$application->hasSSOEnabled()) {
            throw new Exception('SSO is not enabled for this application');
        }

        $config = $application->ssoConfiguration;
        
        // Validate redirect URI
        if (!$this->isValidRedirectUri($redirectUri, $config)) {
            throw ValidationException::withMessages([
                'redirect_uri' => 'Invalid redirect URI for this application'
            ]);
        }

        // Check if user has access to this application
        if (!$this->userCanAccessApplication($user, $application)) {
            throw new Exception('User does not have access to this application');
        }

        // Create or update SSO session
        $session = $this->createOrUpdateSession($user, $application, $ipAddress, $userAgent);

        // Generate authorization code (temporary)
        $authCode = Str::random(32);
        
        // Store auth code in session metadata for validation
        $session->update([
            'metadata' => array_merge($session->metadata ?? [], [
                'auth_code' => $authCode,
                'auth_code_expires' => now()->addMinutes(10)->timestamp,
                'redirect_uri' => $redirectUri,
            ])
        ]);

        return [
            'auth_code' => $authCode,
            'redirect_uri' => $redirectUri,
            'expires_in' => 600, // 10 minutes
            'state' => $session->session_token,
        ];
    }

    /**
     * Validate callback and exchange auth code for session token
     */
    public function validateCallback(
        string $authCode, 
        int $applicationId,
        string $redirectUri = null
    ): array {
        $application = Application::findOrFail($applicationId);
        
        // Find session with this auth code
        $session = SSOSession::where('application_id', $applicationId)
            ->whereJsonContains('metadata->auth_code', $authCode)
            ->active()
            ->first();

        if (!$session) {
            throw new Exception('Invalid or expired authorization code');
        }

        $metadata = $session->metadata ?? [];
        
        // Check auth code expiration
        if (!isset($metadata['auth_code_expires']) || 
            now()->timestamp > $metadata['auth_code_expires']) {
            throw new Exception('Authorization code has expired');
        }

        // Validate redirect URI if provided
        if ($redirectUri && isset($metadata['redirect_uri']) && 
            $metadata['redirect_uri'] !== $redirectUri) {
            throw new Exception('Redirect URI mismatch');
        }

        // Clear auth code from metadata
        unset($metadata['auth_code'], $metadata['auth_code_expires']);
        $session->update(['metadata' => $metadata]);

        return [
            'access_token' => $session->session_token,
            'refresh_token' => $session->refresh_token,
            'token_type' => 'Bearer',
            'expires_in' => $session->expires_at->timestamp - now()->timestamp,
            'user' => [
                'id' => $session->user->id,
                'name' => $session->user->name,
                'email' => $session->user->email,
            ]
        ];
    }

    /**
     * Validate session token
     */
    public function validateSession(string $sessionToken): ?SSOSession
    {
        $session = SSOSession::with(['user', 'application'])
            ->where('session_token', $sessionToken)
            ->active()
            ->first();

        if ($session) {
            $session->updateActivity();
        }

        return $session;
    }

    /**
     * Refresh SSO session
     */
    public function refreshSession(string $refreshToken): array
    {
        $session = SSOSession::where('refresh_token', $refreshToken)
            ->active()
            ->first();

        if (!$session) {
            throw new Exception('Invalid or expired refresh token');
        }

        // Extend session and generate new refresh token
        $session->extend();
        $newRefreshToken = $session->refresh();

        return [
            'access_token' => $session->session_token,
            'refresh_token' => $newRefreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $session->expires_at->timestamp - now()->timestamp,
        ];
    }

    /**
     * Synchronize logout across applications
     */
    public function synchronizeLogout(string $sessionToken): array
    {
        $session = SSOSession::with(['application.ssoConfiguration'])
            ->where('session_token', $sessionToken)
            ->first();

        if (!$session) {
            throw new Exception('Session not found');
        }

        $application = $session->application;
        $config = $application->ssoConfiguration;
        
        // Revoke the session
        $session->revoke();

        // Prepare logout URLs for all active sessions of this user
        $logoutUrls = [];
        $activeSessions = SSOSession::with(['application.ssoConfiguration'])
            ->where('user_id', $session->user_id)
            ->where('id', '!=', $session->id)
            ->active()
            ->get();

        foreach ($activeSessions as $activeSession) {
            if ($activeSession->application->ssoConfiguration) {
                $logoutUrls[] = $activeSession->application->ssoConfiguration->logout_url;
                $activeSession->revoke(); // Revoke all other sessions
            }
        }

        return [
            'logout_urls' => array_unique($logoutUrls),
            'revoked_sessions' => $activeSessions->count() + 1,
        ];
    }

    /**
     * Get SSO configuration for an application
     */
    public function getConfiguration(int $applicationId): SSOConfiguration
    {
        $application = Application::with('ssoConfiguration')->findOrFail($applicationId);
        
        if (!$application->ssoConfiguration) {
            throw new Exception('SSO is not configured for this application');
        }

        return $application->ssoConfiguration;
    }

    /**
     * Create SSO configuration for an application
     */
    public function createConfiguration(
        int $applicationId,
        string $logoutUrl,
        string $callbackUrl,
        array $allowedDomains,
        int $sessionLifetime = 3600,
        array $settings = []
    ): SSOConfiguration {
        $application = Application::findOrFail($applicationId);

        // Check if configuration already exists
        if ($application->ssoConfiguration) {
            throw new Exception('SSO configuration already exists for this application');
        }

        return SSOConfiguration::create([
            'application_id' => $applicationId,
            'logout_url' => $logoutUrl,
            'callback_url' => $callbackUrl,
            'allowed_domains' => $allowedDomains,
            'session_lifetime' => $sessionLifetime,
            'settings' => $settings,
        ]);
    }

    /**
     * Update SSO configuration
     */
    public function updateConfiguration(
        int $applicationId,
        array $updates
    ): SSOConfiguration {
        $application = Application::with('ssoConfiguration')->findOrFail($applicationId);
        
        if (!$application->ssoConfiguration) {
            throw new Exception('SSO configuration does not exist for this application');
        }

        $application->ssoConfiguration->update($updates);
        
        return $application->ssoConfiguration->fresh();
    }

    /**
     * Get active sessions for a user
     */
    public function getUserActiveSessions(int $userId): \Illuminate\Database\Eloquent\Collection
    {
        return SSOSession::with(['application'])
            ->where('user_id', $userId)
            ->active()
            ->orderBy('last_activity_at', 'desc')
            ->get();
    }

    /**
     * Revoke all sessions for a user
     */
    public function revokeUserSessions(int $userId): int
    {
        return SSOSession::where('user_id', $userId)
            ->active()
            ->update(['expires_at' => now()->subSecond()]);
    }

    /**
     * Clean up expired sessions
     */
    public function cleanupExpiredSessions(): int
    {
        return SSOSession::expired()->delete();
    }

    private function isValidRedirectUri(string $redirectUri, SSOConfiguration $config): bool
    {
        $parsedUri = parse_url($redirectUri);
        
        if (!$parsedUri || !isset($parsedUri['host'])) {
            return false;
        }

        return $config->isAllowedDomain($parsedUri['host']);
    }

    private function userCanAccessApplication(User $user, Application $application): bool
    {
        // Check if user belongs to the same organization
        if ($user->organization_id !== $application->organization_id) {
            return false;
        }

        // Check if user has access to this specific application
        return $user->applications()->where('application_id', $application->id)->exists();
    }

    private function createOrUpdateSession(
        User $user, 
        Application $application, 
        string $ipAddress, 
        string $userAgent
    ): SSOSession {
        // Look for existing active session
        $existingSession = SSOSession::where('user_id', $user->id)
            ->where('application_id', $application->id)
            ->active()
            ->first();

        if ($existingSession) {
            // Extend existing session
            $existingSession->extend();
            $existingSession->update([
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
            ]);
            
            return $existingSession;
        }

        // Create new session
        $config = $application->ssoConfiguration;
        $sessionLifetime = $config->getSessionLifetimeInSeconds();

        return SSOSession::create([
            'user_id' => $user->id,
            'application_id' => $application->id,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'expires_at' => now()->addSeconds($sessionLifetime),
        ]);
    }
}