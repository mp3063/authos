<?php

namespace App\Services\SSO;

use App\Models\Application;
use App\Models\SSOSession;
use App\Models\User;
use Exception;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class SsoSessionManager
{
    /**
     * Validate session token
     */
    public function validateSession(string $sessionToken): ?SSOSession
    {
        $session = SSOSession::with(['user', 'application'])
            ->where('session_token', $sessionToken)
            ->active()
            ->first();

        // Check if session exists before calling updateActivity
        if ($session) {
            $session->updateActivity();
        }

        return $session;
    }

    /**
     * Refresh SSO session
     *
     * @throws Exception
     */
    public function refreshSession(string $refreshToken): array
    {
        $session = SSOSession::where('refresh_token', $refreshToken)
            ->active()
            ->first();

        if (! $session) {
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
     *
     * @throws Exception
     */
    public function synchronizeLogout(string $sessionToken): array
    {
        $session = SSOSession::with(['application.ssoConfiguration'])
            ->where('session_token', $sessionToken)
            ->first();

        if (! $session) {
            throw new Exception('Session not found');
        }

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
     * Get active sessions for a user
     *
     * @return Collection<int, SSOSession>
     */
    public function getUserActiveSessions(int $userId): Collection
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
    public function revokeUserSessions(int $userId, ?int $applicationId = null): int
    {
        // Get all sessions that are not already logged out
        $sessions = SSOSession::where('user_id', $userId)
            ->when($applicationId !== null, fn ($query) => $query->where('application_id', $applicationId))
            ->whereNull('logged_out_at')
            ->get();

        $updatedCount = 0;
        foreach ($sessions as $session) {
            $session->update([
                'expires_at' => now()->subSecond(),
                'logged_out_at' => now(),
                'logged_out_by' => $userId,
            ]);
            $updatedCount++;
        }

        return $updatedCount;
    }

    /**
     * Clean up expired sessions
     */
    public function cleanupExpiredSessions(): int
    {
        $deletedCount = SSOSession::expired()->delete();

        return $deletedCount ?: 0;
    }

    /**
     * Revoke a specific SSO session
     *
     * @throws Exception
     */
    public function revokeSSOSession(string $sessionToken, int $userId): bool
    {
        $session = SSOSession::where('session_token', $sessionToken)->first();

        if (! $session) {
            throw new Exception('SSO session not found');
        }

        if ($session->user_id !== $userId) {
            throw new Exception('Not authorized to revoke this session');
        }

        return $session->logout($userId);
    }

    /**
     * Validate SSO session token
     *
     * @throws Exception
     */
    public function validateSSOSession(string $sessionToken): ?SSOSession
    {
        $session = SSOSession::with(['user', 'application'])
            ->where('session_token', $sessionToken)
            ->first();

        if (! $session) {
            throw new Exception('Invalid SSO session token');
        }

        if ($session->isExpired()) {
            throw new Exception('Session has expired');
        }

        if ($session->logged_out_at !== null) {
            throw new Exception('SSO session has been logged out');
        }

        $session->updateActivity();

        return $session;
    }

    /**
     * Synchronized logout for a user (logout from all applications)
     */
    public function synchronizedLogout(int $userId): bool
    {
        try {
            $revokedCount = $this->revokeUserSessions($userId);

            // Clear cache for user sessions
            Cache::forget("sso_sessions:{$userId}");

            Log::info('Synchronized logout completed', [
                'user_id' => $userId,
                'revoked_sessions' => $revokedCount,
            ]);

            return true;
        } catch (Exception) {
            Log::error('Synchronized logout failed', [
                'user_id' => $userId,
            ]);

            return false;
        }
    }

    public function createOrUpdateSession(
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

    /**
     * Update session metadata with new data
     */
    public function updateSessionMetadata(SSOSession $session, array $newData): void
    {
        $session->metadata = array_merge($session->metadata ?? [], $newData);
        $session->save();
    }
}
