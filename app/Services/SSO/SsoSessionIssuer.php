<?php

namespace App\Services\SSO;

use App\Models\SSOConfiguration;
use App\Models\User;
use App\Services\Auth\MfaChallengeStore;
use App\Services\Auth\MfaSetupTokenIssuer;
use App\Services\AuthenticationLogService;
use Illuminate\Http\JsonResponse;

class SsoSessionIssuer
{
    public function __construct(
        private readonly SsoSessionManager $sessions,
        private readonly MfaChallengeStore $challenges,
        private readonly MfaSetupTokenIssuer $setupTokens,
        private readonly AuthenticationLogService $authLogService,
    ) {}

    /**
     * @param  array{ip_address: string, user_agent: string, metadata?: array<string, mixed>}  $attributes
     */
    public function issue(User $user, SSOConfiguration $configuration, array $attributes): array
    {
        $application = $configuration->application->setRelation('ssoConfiguration', $configuration);
        $session = $this->sessions->createOrUpdateSession($user, $application, $attributes['ip_address'], $attributes['user_agent']);
        $this->sessions->updateSessionMetadata($session, $attributes['metadata'] ?? []);

        return [
            'success' => true,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ],
            'session' => [
                'id' => $session->id,
                'session_token' => $session->session_token,
                'token' => $session->session_token,
                'expires_at' => $session->expires_at->toISOString(),
            ],
            'application' => [
                'id' => $application->id,
                'name' => $application->name,
            ],
            'tokens' => [
                'access_token' => $session->session_token,
                'token_type' => 'Bearer',
                'expires_in' => $session->expires_at->timestamp - now()->timestamp,
            ],
        ];
    }

    /**
     * @param  array{ip_address: string, user_agent: string, metadata?: array<string, mixed>}  $attributes
     */
    public function challenge(User $user, SSOConfiguration $configuration, array $attributes): array
    {
        if ($user->mustSetUpMfa()) {
            $this->authLogService->logAuthenticationEvent($user, 'mfa_setup_required', ['sso_configuration_id' => $configuration->id]);

            return ['mfa_setup_required' => true, ...$this->setupTokens->issue($user)];
        }

        $this->authLogService->logAuthenticationEvent($user, 'mfa_required', ['sso_configuration_id' => $configuration->id]);

        return [
            'mfa_required' => true,
            'challenge_token' => $this->challenges->create($user, [
                'kind' => 'sso',
                'sso_configuration_id' => $configuration->id,
                'attributes' => $attributes,
            ]),
            'available_methods' => $user->getMfaMethods(),
        ];
    }

    public function challengeResponse(array $result): ?JsonResponse
    {
        if ($result['mfa_setup_required'] ?? false) {
            return response()->json([
                'message' => 'Your organization requires multi-factor authentication. Set it up to continue.',
                'error' => 'mfa_setup_required',
                'mfa_setup_required' => true,
                'setup_token' => $result['setup_token'],
                'token_type' => $result['token_type'],
                'expires_in' => $result['expires_in'],
            ], 403);
        }

        if ($result['mfa_required'] ?? false) {
            return response()->json([
                'message' => 'Multi-factor authentication is required',
                'mfa_required' => true,
                'challenge_token' => $result['challenge_token'],
                'available_methods' => $result['available_methods'],
            ], 202);
        }

        return null;
    }
}
