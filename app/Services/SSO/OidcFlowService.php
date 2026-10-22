<?php

namespace App\Services\SSO;

use App\Models\AuthenticationLog;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use Exception;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;

class OidcFlowService
{
    public function __construct(
        private readonly SsoSessionManager $sessions,
        private readonly SsoSessionIssuer $issuer,
    ) {}

    /**
     * Handle OIDC callback processing
     *
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function handleOIDCCallback(array $callbackData): array
    {
        // Extract authorization code and state from callback data
        $authCode = $callbackData['code'] ?? null;
        $state = $callbackData['state'] ?? null;

        if (! $authCode) {
            throw new InvalidArgumentException('Authorization code is required');
        }

        if (! $state) {
            throw new InvalidArgumentException('State parameter is required');
        }

        $session = $this->findPendingSession($state, $authCode);

        try {
            return $this->completeCallback($session, $state, $authCode);
        } finally {
            $session->delete();
        }
    }

    /**
     * @throws Exception
     */
    private function completeCallback(SSOSession $session, string $state, string $authCode): array
    {
        $this->assertCallbackSessionUsable($session, $state, $authCode);
        $ssoConfig = $session->application->ssoConfiguration;

        if (! $ssoConfig) {
            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_config_missing', false, [
                'error' => 'SSO configuration not found',
            ]);
            throw new Exception('SSO configuration not found');
        }

        // Mark authorization code as used to prevent replay attacks
        $sessionMetadata = $session->metadata ?? [];
        $sessionMetadata['auth_code_used'] = true;
        $sessionMetadata['auth_code_used_at'] = now()->toISOString();
        $session->metadata = $sessionMetadata;
        $session->save();

        $exchange = $this->exchangeAuthorizationCode($session, $ssoConfig, $authCode);

        if ($exchange === null) {
            return [
                'success' => false,
                'error' => 'SSO authentication failed',
            ];
        }

        $user = $session->user;
        $attributes = [
            'ip_address' => $session->ip_address,
            'user_agent' => $session->user_agent,
            'metadata' => array_merge(Arr::except($session->metadata ?? [], ['pending']), [
                'access_token' => $exchange['access_token'],
                'id_token' => $exchange['id_token'],
                'refresh_token' => $exchange['refresh_token'],
                'user_info' => $exchange['user_info'],
            ]),
        ];

        if ($user->requiresMfa()) {
            return $this->issuer->challenge($user, $ssoConfig, $attributes);
        }

        $result = $this->issuer->issue($user, $ssoConfig, $attributes);

        $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_login_success', true, [
            'provider' => 'oidc',
            'session_id' => $result['session']['id'],
        ]);

        return $result;
    }

    /**
     * Refresh SSO token
     *
     * @throws Exception
     */
    public function refreshSSOToken(string $sessionToken, ?int $applicationId = null): array
    {
        $query = SSOSession::where('session_token', $sessionToken)->active();

        if ($applicationId !== null) {
            $query->where('application_id', $applicationId);
        }

        $session = $query->first();

        if (! $session) {
            throw new Exception('Invalid or expired refresh token');
        }

        $application = $session->application;
        $idpRefreshToken = $this->nonEmptyString($session->metadata['refresh_token'] ?? null);

        try {
            $ssoConfig = $application->ssoConfiguration;

            if ($idpRefreshToken === null) {
                throw new Exception('Session has no IdP refresh token');
            }

            if (! $ssoConfig || empty($ssoConfig->configuration['token_endpoint'])) {
                throw new Exception('Token endpoint not configured');
            }

            $response = Http::connectTimeout(10)->timeout(30)->post($ssoConfig->configuration['token_endpoint'], [
                'grant_type' => 'refresh_token',
                'refresh_token' => $idpRefreshToken,
                'client_id' => $ssoConfig->configuration['client_id'] ?? '',
                'client_secret' => $ssoConfig->configuration['client_secret'] ?? '',
            ]);

            $tokenData = $response->successful() ? $response->json() : null;
            $newAccessToken = $this->nonEmptyString($tokenData['access_token'] ?? null);

            if ($newAccessToken === null) {
                throw new Exception('Token refresh failed');
            }

            $newRefreshToken = $this->nonEmptyString($tokenData['refresh_token'] ?? null) ?? $idpRefreshToken;
        } catch (Exception) {
            throw new Exception('Invalid or expired refresh token');
        }

        $this->sessions->updateSessionMetadata($session, [
            'access_token' => $newAccessToken,
            'refresh_token' => $newRefreshToken,
            'token_updated_at' => now()->toISOString(),
        ]);

        return [
            'success' => true,
            'access_token' => $newAccessToken,
            'refresh_token' => $newRefreshToken,
            'token_type' => 'Bearer',
            'expires_at' => $session->expires_at->toISOString(),
            'expires_in' => $session->expires_at->timestamp - now()->timestamp,
        ];
    }

    /**
     * @throws Exception
     */
    private function findPendingSession(string $state, string $authCode): SSOSession
    {
        $session = SSOSession::pending()->where('external_session_id', $state)->first();

        if (! $session) {
            // Log authentication failure
            $this->logAuthenticationEvent(null, null, 'sso_callback_failed', false, [
                'error' => 'Invalid state parameter',
                'state' => $state,
                'code' => $authCode,
            ]);
            throw new Exception('Invalid or expired authorization code');
        }

        return $session;
    }

    /**
     * @throws Exception
     */
    private function assertCallbackSessionUsable(SSOSession $session, string $state, string $authCode): void
    {
        // Check for replay attack - validate state matches session metadata
        $sessionMetadata = $session->metadata ?? [];
        if (($sessionMetadata['state'] ?? null) !== $state) {
            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_replay_attack', false, [
                'error' => 'State parameter mismatch - possible replay attack',
                'session_state' => $sessionMetadata['state'] ?? 'missing',
                'provided_state' => $state,
            ]);
            throw new Exception('Invalid state parameter');
        }

        // Check for authorization code replay - mark code as used
        if (isset($sessionMetadata['auth_code_used']) && $sessionMetadata['auth_code_used']) {
            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_replay_attack', false, [
                'error' => 'Authorization code already used',
                'code' => $authCode,
            ]);
            throw new Exception('Authorization code has already been used');
        }

        if (! $session->isActive()) {
            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_session_expired', false, [
                'error' => 'Session is not active',
                'session_id' => $session->id,
            ]);
            throw new Exception('Session is not active');
        }
    }

    /**
     * Exchange the auth code for tokens and the IdP identity; null means the flow must abort.
     *
     * @return array{access_token: string, id_token: ?string, refresh_token: ?string, user_info: array<string, mixed>}|null
     */
    private function exchangeAuthorizationCode(SSOSession $session, SSOConfiguration $ssoConfig, string $authCode): ?array
    {
        try {
            $tokenResponse = Http::connectTimeout(10)->timeout(30)->post($ssoConfig->configuration['token_endpoint'], [
                'grant_type' => 'authorization_code',
                'code' => $authCode,
                'redirect_uri' => $ssoConfig->callback_url,
                'client_id' => $ssoConfig->configuration['client_id'] ?? '',
                'client_secret' => $ssoConfig->configuration['client_secret'] ?? '',
            ]);

            $tokenData = $tokenResponse->successful() ? $tokenResponse->json() : null;
            $accessToken = $this->nonEmptyString($tokenData['access_token'] ?? null);

            if ($accessToken === null) {
                $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_token_exchange_failed', false, [
                    'error' => $tokenResponse->successful() ? 'Token response has no access_token' : 'Token exchange failed',
                    'http_status' => $tokenResponse->status(),
                ]);

                return null;
            }

            $userInfo = $this->fetchUserInfo($ssoConfig, $accessToken);
        } catch (ConnectionException $e) {
            report($e);

            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_connection_timeout', false, [
                'error' => 'Connection timeout',
            ]);

            return null;
        } catch (Exception $e) {
            report($e);

            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_http_error', false, [
                'error' => 'HTTP request failed',
            ]);

            return null;
        }

        if ($userInfo === null) {
            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_userinfo_failed', false, [
                'error' => 'Userinfo request failed',
            ]);

            return null;
        }

        if (! $this->identityMatchesSessionUser($userInfo, $session)) {
            $this->logAuthenticationEvent($session->user_id, $session->application_id, 'sso_identity_mismatch', false, [
                'error' => 'IdP email does not match the session user',
            ]);

            return null;
        }

        return [
            'access_token' => $accessToken,
            'id_token' => $this->nonEmptyString($tokenData['id_token'] ?? null),
            'refresh_token' => $this->nonEmptyString($tokenData['refresh_token'] ?? null),
            'user_info' => $userInfo,
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function fetchUserInfo(SSOConfiguration $ssoConfig, string $accessToken): ?array
    {
        try {
            $userInfoResponse = Http::connectTimeout(10)->timeout(30)->withToken($accessToken)
                ->get($ssoConfig->configuration['userinfo_endpoint'] ?? '');
        } catch (ConnectionException) {
            return null;
        }

        $userInfo = $userInfoResponse->successful() ? $userInfoResponse->json() : null;

        return is_array($userInfo) ? $userInfo : null;
    }

    /**
     * @param  array<string, mixed>  $userInfo
     */
    private function identityMatchesSessionUser(array $userInfo, SSOSession $session): bool
    {
        $email = $userInfo['email'] ?? null;

        return is_string($email) && mb_strtolower($email) === mb_strtolower($session->user->email);
    }

    private function nonEmptyString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Log authentication events for audit trail
     */
    private function logAuthenticationEvent(?int $userId, ?int $applicationId, string $event, bool $success, array $metadata = []): void
    {
        try {
            AuthenticationLog::create([
                'user_id' => $userId,
                'application_id' => $applicationId,
                'event' => $event,
                'success' => $success,
                'ip_address' => request()->ip() ?? '127.0.0.1',
                'user_agent' => request()->userAgent() ?? 'Unknown',
                'metadata' => $metadata,
            ]);
        } catch (Exception $e) {
            Log::error('Failed to log authentication event', [
                'error' => $e->getMessage(),
                'event' => $event,
                'user_id' => $userId,
            ]);
        }
    }
}
