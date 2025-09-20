<?php

namespace App\Services;

use App\Models\AuthenticationLog;
use App\Models\User;
use Illuminate\Http\Request;

class AuthenticationLogService
{
    /**
     * Log an authentication event
     */
    public function logAuthenticationEvent(User $user, string $event, array $metadata = [], ?Request $request = null, ?bool $success = null): void
    {
        $request = $request ?? request();

        // Determine success if not explicitly provided
        if ($success === null) {
            $failureEvents = ['login_failed', 'failed_mfa', 'oauth_token_failed', 'social_login_failed', 'account_locked'];
            $success = ! in_array($event, $failureEvents);
        }

        AuthenticationLog::create([
            'user_id' => $user->id,
            'event' => $event,
            'ip_address' => $request->ip() ?: '127.0.0.1',
            'user_agent' => $request->userAgent() ?: 'Unknown',
            'metadata' => $metadata,
            'success' => $success,
            'created_at' => now(),
        ]);
    }

    /**
     * Log authentication event with better signature compatibility
     */
    public function logAuthenticationEventWithDetails(
        User $user,
        string $event,
        Request $request,
        ?string $clientId = null,
        bool $successful = true
    ): void {
        $userAgent = $request->userAgent() ?: 'Unknown';
        $ipAddress = $request->ip() ?: '127.0.0.1';

        $metadata = [
            'client_id' => $clientId,
            'user_agent' => $userAgent,
            'ip_address' => $ipAddress,
        ];

        AuthenticationLog::create([
            'user_id' => $user->id,
            'event' => $event,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'metadata' => $metadata,
            'success' => $successful,
            'created_at' => now(),
        ]);
    }

    /**
     * Get user info for OpenID Connect
     */
    public function getUserInfo(User $user, array $scopes = []): array
    {
        $userInfo = [
            'sub' => (string) $user->id,
        ];

        if (in_array('profile', $scopes)) {
            $userInfo['name'] = $user->name;
            $userInfo['preferred_username'] = $user->name;
            $userInfo['updated_at'] = $user->updated_at?->timestamp;
        }

        if (in_array('email', $scopes)) {
            $userInfo['email'] = $user->email;
            $userInfo['email_verified'] = $user->email_verified_at !== null;
        }

        return $userInfo;
    }
}
