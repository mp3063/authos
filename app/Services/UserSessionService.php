<?php

namespace App\Services;

use App\Models\AuthenticationLog;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Collection;

class UserSessionService
{
    /**
     * Get user's active OAuth tokens (sessions)
     */
    public function getUserSessions(User $user): EloquentCollection
    {
        // Get OAuth access tokens (Passport) for this user
        return $user->tokens()
            ->where('revoked', false)
            ->orderBy('created_at', 'desc')
            ->get();
    }

    /**
     * Revoke all user OAuth tokens (sessions)
     */
    public function revokeAllUserSessions(User $user): int
    {
        // Get all active OAuth tokens for this user
        $activeTokens = $user->tokens()->where('revoked', false)->get();
        $revokedCount = $activeTokens->count();

        // Revoke each token
        foreach ($activeTokens as $token) {
            $token->revoke();
        }

        // Log session revocation
        if (request()) {
            AuthenticationLog::create([
                'user_id' => $user->id,
                'event' => 'all_sessions_revoked',
                'success' => true,
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'details' => [],
            ]);
        }

        return $revokedCount;
    }

    /**
     * Revoke specific user OAuth token (session)
     */
    public function revokeUserSession(User $user, string $sessionId): bool
    {
        // Find the specific OAuth token
        $token = $user->tokens()->where('id', $sessionId)->first();

        if (! $token) {
            return false;
        }

        // Revoke the token
        $token->revoke();

        // Log session revocation
        if (request()) {
            AuthenticationLog::create([
                'user_id' => $user->id,
                'event' => 'session_revoked',
                'success' => true,
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'details' => ['token_id' => $sessionId],
            ]);
        }

        return true;
    }

    /**
     * Format user OAuth tokens (sessions) response
     */
    public function formatUserSessionsResponse(Collection $sessions): array
    {
        return $sessions->map(function ($token) {
            // Decode scopes from JSON if it's a string
            $scopes = $token->scopes;
            if (is_string($scopes)) {
                $scopes = json_decode($scopes, true) ?? [];
            }

            return [
                'id' => $token->id,
                'name' => $token->name,
                'scopes' => $scopes ?? [],
                'created_at' => $token->created_at?->toISOString(),
                'expires_at' => $token->expires_at?->toISOString(),
                'last_used_at' => $token->updated_at?->toISOString(),
                'revoked' => (bool) $token->revoked,
            ];
        })->toArray();
    }
}
