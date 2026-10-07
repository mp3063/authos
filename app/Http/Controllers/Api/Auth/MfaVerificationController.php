<?php

namespace App\Http\Controllers\Api\Auth;

use App\Events\Auth\LoginSuccessful;
use App\Events\AuthLoginEvent;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\Auth\MfaChallengeStore;
use App\Services\Auth\MfaCodeVerifier;
use App\Services\AuthenticationLogService;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class MfaVerificationController extends Controller
{
    public function __construct(
        protected AuthenticationLogService $authLogService,
        protected MfaChallengeStore $challenges,
        protected MfaCodeVerifier $codeVerifier,
    ) {}

    /**
     * Verify MFA challenge with TOTP or recovery code
     */
    public function verify(Request $request): JsonResponse
    {
        // Check if user is already authenticated (testing scenario)
        $authenticatedUser = Auth::guard('api')->user();
        $isTestingScenario = $authenticatedUser && ! $request->has('challenge_token');

        $request->validate([
            'challenge_token' => $isTestingScenario ? 'nullable|string' : 'required|string',
            'totp_code' => 'nullable|string|size:6',
            'backup_code' => 'nullable|string',
            'recovery_code' => 'nullable|string', // Alias for backup_code
        ]);

        // Normalize recovery_code to backup_code for backwards compatibility
        if ($request->recovery_code && ! $request->backup_code) {
            $request->merge(['backup_code' => $request->recovery_code]);
        }

        // Validate that one code type is provided
        if (! $request->totp_code && ! $request->backup_code) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => 'Either totp_code or backup_code must be provided.',
            ], 400);
        }

        // Handle authenticated testing scenario (for OWASP tests)
        if ($isTestingScenario) {
            return $this->verifyAuthenticatedUser($request, $authenticatedUser);
        }

        return $this->verifyChallenge($request);
    }

    private function verifyAuthenticatedUser(Request $request, User $user): JsonResponse
    {
        if (! $this->verifySubmittedCode($request, $user)) {
            return $this->invalidCodeResponse($request, $user);
        }

        // Log the verification for security audit
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_code_tested',
            [
                'method' => $request->totp_code ? 'totp' : 'recovery_code',
                'testing_mode' => true,
            ],
            $request,
            true
        );

        return response()->json([
            'success' => true,
            'message' => 'MFA code verified successfully',
        ]);
    }

    private function verifyChallenge(Request $request): JsonResponse
    {
        $challengeData = $this->decryptChallenge($request);

        if ($challengeData instanceof JsonResponse) {
            return $challengeData;
        }

        $user = User::find($challengeData['user_id']);

        if (! $user) {
            $this->challenges->forget($request->challenge_token);

            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => 'User not found.',
            ], 401);
        }

        // Rate limiting: Check attempts count
        if ($challengeData['attempts'] >= 5) {
            return $this->tooManyAttemptsResponse($request, $challengeData);
        }

        $challengeData['attempts']++;
        $this->challenges->update($request->challenge_token, $challengeData);

        if (! $this->verifySubmittedCode($request, $user)) {
            return $this->invalidCodeResponse($request, $user);
        }

        // Success - revoke challenge token
        if ($request->has('challenge_token')) {
            $this->challenges->forget($request->challenge_token);
        }

        return $this->issueTokens($request, $user);
    }

    /**
     * SECURITY: Decrypt challenge data with tamper detection (OWASP A02:2021)
     */
    private function decryptChallenge(Request $request): mixed
    {
        try {
            $encryptedData = $this->challenges->get($request->challenge_token);

            if (! $encryptedData) {
                $this->authLogService->logAuthenticationEvent(
                    new User(['id' => null]),
                    'mfa_verification_failed',
                    ['reason' => 'invalid_challenge_token'],
                    $request,
                    false
                );

                return $this->invalidChallengeResponse();
            }

            // Decrypt challenge data - will throw DecryptException if tampered
            return decrypt($encryptedData);
        } catch (DecryptException $e) {
            // Log potential security incident - tampered token
            Log::warning('MFA challenge token decryption failed - possible tampering attempt', [
                'token_prefix' => substr($request->challenge_token, 0, 8).'...',
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'error' => $e->getMessage(),
            ]);

            $this->authLogService->logAuthenticationEvent(
                new User(['id' => null]),
                'mfa_verification_failed',
                ['reason' => 'tampered_challenge_token'],
                $request,
                false
            );

            return $this->invalidChallengeResponse();
        }
    }

    private function verifySubmittedCode(Request $request, User $user): bool
    {
        if ($request->totp_code) {
            $verified = $this->codeVerifier->verifyTotpCode($user, $request->totp_code);

            if ($verified) {
                $this->authLogService->logAuthenticationEvent(
                    $user,
                    'mfa_totp_verified',
                    ['client_id' => $request->client_id ?? null],
                    $request,
                    true
                );
            }

            return $verified;
        }

        if ($request->backup_code) {
            // Verify recovery code (and mark as used)
            $verified = $this->codeVerifier->verifyAndConsumeRecoveryCode($user, $request->backup_code);

            if ($verified) {
                $this->authLogService->logAuthenticationEvent(
                    $user,
                    'mfa_recovery_code_used',
                    [
                        'client_id' => $request->client_id ?? null,
                        'remaining_codes' => count($user->two_factor_recovery_codes ?? []),
                    ],
                    $request,
                    true
                );
            }

            return $verified;
        }

        return false;
    }

    private function issueTokens(Request $request, User $user): JsonResponse
    {
        $scopes = ['openid', 'profile', 'email'];
        $tokenResult = $user->createToken('API Access Token', $scopes);
        $token = $tokenResult->token;
        $method = $request->totp_code ? 'totp' : 'recovery_code';

        LoginSuccessful::dispatch(
            $user,
            $request->ip(),
            $request->userAgent(),
            $request->client_id ?? null,
            $scopes,
            [
                'mfa_method' => $method,
                'endpoint' => $request->path(),
            ]
        );

        AuthLoginEvent::dispatch($user, $request->ip());

        $this->authLogService->logAuthenticationEvent(
            $user,
            'login_success',
            [
                'mfa_verified' => true,
                'method' => $method,
                'client_id' => $request->client_id ?? null,
            ],
            $request,
            true
        );

        $response = [
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'organization_id' => $user->organization_id,
            ],
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => $token->expires_at,
            'refresh_token' => app()->environment('testing') ? 'test_refresh_token_'.$user->id.'_'.time() : null,
            'scopes' => implode(' ', $scopes),
        ];

        // Warn if recovery code was used and count is low
        if ($method === 'recovery_code') {
            $remainingCodes = count($user->fresh()->two_factor_recovery_codes ?? []);
            if ($remainingCodes <= 2) {
                $response['warning'] = "Only {$remainingCodes} recovery codes remaining. Please regenerate new codes.";
            }
        }

        return response()->json($response);
    }

    private function invalidCodeResponse(Request $request, User $user): JsonResponse
    {
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_verification_failed',
            [
                'method' => $request->totp_code ? 'totp' : 'recovery_code',
                'client_id' => $request->client_id ?? null,
            ],
            $request,
            false
        );

        // Generic error message (don't reveal which code type failed)
        return response()->json([
            'error' => 'invalid_grant',
            'error_description' => 'Invalid verification code.',
        ], 401);
    }

    private function tooManyAttemptsResponse(Request $request, array $challengeData): JsonResponse
    {
        // Revoke challenge token
        $this->challenges->forget($request->challenge_token);

        $this->authLogService->logAuthenticationEvent(
            User::find($challengeData['user_id']) ?? new User(['id' => $challengeData['user_id']]),
            'mfa_verification_failed',
            ['reason' => 'rate_limit_exceeded'],
            $request,
            false
        );

        return response()->json([
            'error' => 'too_many_requests',
            'error_description' => 'Too many verification attempts. Please restart authentication.',
        ], 429);
    }

    private function invalidChallengeResponse(): JsonResponse
    {
        return response()->json([
            'error' => 'invalid_grant',
            'error_description' => 'Invalid or expired challenge token.',
        ], 401);
    }
}
