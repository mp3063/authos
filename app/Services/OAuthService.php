<?php

namespace App\Services;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Client;
use Laravel\Passport\PersonalAccessTokenResult;

class OAuthService
{
    public function __construct()
    {
        //
    }

    /**
     * Create a new OAuth client for an application
     */
    public function createClient(Application $application, bool $personalAccess = false, bool $passwordGrant = false): ?Client
    {
        // Use Laravel Passport's Client model directly
        $client = Client::create([
            'user_id' => null,
            'name' => $application->name,
            'redirect' => implode(',', $application->redirect_uris ?? []),
            'personal_access_client' => $personalAccess,
            'password_client' => $passwordGrant,
            'revoked' => false,
            'secret' => $passwordGrant || !$personalAccess ? \Illuminate\Support\Str::random(40) : null,
        ]);

        // Update application with OAuth credentials
        $application->update([
            'client_id' => $client->id,
            'client_secret' => $client->secret,
        ]);

        return $client;
    }

    /**
     * Validate OAuth client credentials
     */
    public function validateClient(string $clientId, ?string $clientSecret = null): ?Client
    {
        $client = Client::find($clientId);

        if (!$client || $client->revoked) {
            return null;
        }

        if ($clientSecret && !Hash::check($clientSecret, $client->secret)) {
            return null;
        }

        return $client;
    }

    /**
     * Generate access token for user
     */
    public function generateAccessToken(User $user, array $scopes = []): PersonalAccessTokenResult
    {
        $scopes = empty($scopes) ? ['openid'] : $scopes;
        return $user->createToken('AuthOS Personal Access Token', $scopes);
    }

    /**
     * Revoke access token
     */
    public function revokeToken(string $tokenId): bool
    {
        $token = \Laravel\Passport\Token::find($tokenId);
        
        if ($token) {
            $token->revoke();
            return true;
        }

        return false;
    }

    /**
     * Validate redirect URI for client
     */
    public function validateRedirectUri(Client $client, string $redirectUri): bool
    {
        $clientRedirects = explode(',', $client->redirect);
        return in_array($redirectUri, $clientRedirects);
    }

    /**
     * Generate authorization code for OAuth flow
     */
    public function generateAuthorizationCode(
        Client $client,
        User $user,
        array $scopes,
        string $redirectUri,
        ?string $state = null,
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = null
    ): string {
        // Implementation would integrate with Laravel Passport's authorization server
        // This is a simplified version for the service layer
        return bin2hex(random_bytes(40));
    }

    /**
     * Log authentication event for OAuth
     */
    public function logAuthenticationEvent(
        User $user,
        string $event,
        Request $request,
        ?string $clientId = null,
        bool $successful = true
    ): void {
        $application = null;
        
        if ($clientId) {
            $application = Application::where('client_id', $clientId)->first();
        }

        AuthenticationLog::create([
            'user_id' => $user->id,
            'application_id' => $application?->id,
            'event' => $event,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'metadata' => [
                'client_id' => $clientId,
                'successful' => $successful,
                'timestamp' => now()->toISOString(),
            ],
            'created_at' => now(),
        ]);
    }

    /**
     * Get user info for OpenID Connect
     */
    public function getUserInfo(User $user, array $scopes): array
    {
        $userInfo = [
            'sub' => (string) $user->id,
        ];

        if (in_array('profile', $scopes)) {
            $userInfo = array_merge($userInfo, [
                'name' => $user->name,
                'preferred_username' => $user->name,
                'updated_at' => $user->updated_at?->timestamp,
            ]);

            if ($user->profile) {
                $userInfo = array_merge($userInfo, [
                    'given_name' => $user->profile['first_name'] ?? null,
                    'family_name' => $user->profile['last_name'] ?? null,
                    'picture' => $user->avatar,
                ]);
            }
        }

        if (in_array('email', $scopes)) {
            $userInfo = array_merge($userInfo, [
                'email' => $user->email,
                'email_verified' => !is_null($user->email_verified_at),
            ]);
        }

        return array_filter($userInfo);
    }

    /**
     * Validate PKCE code challenge
     */
    public function validatePKCE(string $codeVerifier, string $codeChallenge, string $method = 'S256'): bool
    {
        if ($method === 'S256') {
            $hash = hash('sha256', $codeVerifier, true);
            $challenge = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
            return $challenge === $codeChallenge;
        }

        if ($method === 'plain') {
            return $codeVerifier === $codeChallenge;
        }

        return false;
    }

    /**
     * Check if client supports PKCE
     */
    public function clientSupportsPKCE(Client $client): bool
    {
        // Check if client is public (no secret) or has PKCE enabled
        return !$client->confidential || ($client->personal_access_client ?? false);
    }
}