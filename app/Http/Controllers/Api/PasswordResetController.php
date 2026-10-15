<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\Api\PasswordResetConfirmRequest;
use App\Http\Requests\Api\PasswordResetRequest;
use App\Models\User;
use App\Notifications\PasswordResetNotification;
use App\Services\Auth\MfaChallengeStore;
use App\Services\Auth\MfaSetupTokenIssuer;
use App\Services\AuthenticationLogService;
use Carbon\Carbon;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class PasswordResetController extends BaseController
{
    public function __construct(
        protected AuthenticationLogService $authLogService,
        protected MfaChallengeStore $mfaChallenges,
        protected MfaSetupTokenIssuer $mfaSetupTokens,
    ) {}

    /**
     * Send password reset link to email
     *
     * POST /api/v1/auth/password/email
     */
    public function sendResetLinkEmail(PasswordResetRequest $request): JsonResponse
    {
        $email = $request->validated()['email'];

        // Find user by email
        $user = User::where('email', $email)->first();

        // SECURITY: Always return success to prevent email enumeration
        // Don't reveal whether the email exists or not
        if (! $user) {
            Hash::make($email);

            // Log failed password reset attempt
            $this->authLogService->logAuthenticationEvent(
                new User(['email' => $email]),
                'password_reset_requested',
                ['status' => 'email_not_found'],
                $request
            );

            return response()->json([
                'message' => 'If that email address is in our system, we have sent a password reset link to it.',
            ]);
        }

        $token = Password::broker()->createToken($user);

        // Send email notification with plain token (only sent once)
        $user->notify(new PasswordResetNotification($token));

        // Log successful password reset request
        $this->authLogService->logAuthenticationEvent(
            $user,
            'password_reset_requested',
            ['status' => 'success'],
            $request
        );

        // SECURITY: Generic message to prevent enumeration
        return response()->json([
            'message' => 'If that email address is in our system, we have sent a password reset link to it.',
        ]);
    }

    /**
     * Reset password using token
     *
     * POST /api/v1/auth/password/reset
     */
    public function reset(PasswordResetConfirmRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $email = $validated['email'];
        $plainToken = $validated['token'];
        $newPassword = $validated['password'];

        // Find the reset token record
        $resetRecord = DB::table('password_reset_tokens')
            ->where('email', $email)
            ->first();

        $storedHash = $resetRecord->token ?? null;
        $storedHashIsBcrypt = is_string($storedHash) && Hash::info($storedHash)['algoName'] === 'bcrypt';
        $tokenMatches = Hash::check($plainToken, $storedHashIsBcrypt ? $storedHash : $this->dummyTokenHash()) && $storedHashIsBcrypt;
        $tokenCreatedAt = Carbon::parse($resetRecord->created_at ?? now()->subMinutes(30));
        $tokenExpiresAt = $tokenCreatedAt->copy()->addMinutes(60);
        $isValid = $resetRecord && $tokenMatches && now()->lt($tokenExpiresAt);

        // SECURITY: Add random delay (50-150ms) to normalize timing across all responses
        // This prevents attackers from distinguishing between different failure modes
        usleep(random_int(50000, 150000));

        // Check if validation failed
        if (! $isValid) {
            // SECURITY: Always perform DB operation to maintain constant time
            // Clean up expired tokens (if token exists and is expired)
            if ($resetRecord && now()->gte($tokenExpiresAt)) {
                DB::table('password_reset_tokens')
                    ->where('email', $email)
                    ->delete();
            } else {
                // Dummy query to maintain constant time for timing attack protection
                // Prevents attackers from distinguishing expired vs invalid tokens through timing
                DB::table('password_reset_tokens')
                    ->where('email', 'dummy-timing-protection-'.hash('sha256', $email))
                    ->limit(1)
                    ->get();
            }

            // SECURITY: Generic error message that doesn't reveal which check failed
            return response()->json([
                'message' => 'Invalid or expired password reset token.',
                'error' => 'invalid_token',
            ], 422);
        }

        // Find user
        $user = User::where('email', $email)->first();

        if (! $user) {
            // Clean up token even if user not found
            DB::table('password_reset_tokens')
                ->where('email', $email)
                ->delete();

            return response()->json([
                'message' => 'Invalid or expired password reset token.',
                'error' => 'invalid_token',
            ], 422);
        }

        $user->update(['password' => Hash::make($newPassword)]);
        event(new PasswordReset($user));

        // SECURITY: Delete token immediately after use (single-use)
        DB::table('password_reset_tokens')
            ->where('email', $email)
            ->delete();

        // Log password reset success
        $this->authLogService->logAuthenticationEvent(
            $user,
            'password_reset_completed',
            ['status' => 'success'],
            $request
        );

        if ($user->mustSetUpMfa()) {
            $this->authLogService->logAuthenticationEvent($user, 'mfa_setup_required', [], $request);

            return response()->json([
                'message' => 'Your organization requires multi-factor authentication. Set it up to continue.',
                'error' => 'mfa_setup_required',
                ...$this->mfaSetupTokens->issue($user),
            ], 403);
        }

        if ($user->requiresMfa()) {
            $this->authLogService->logAuthenticationEvent($user, 'mfa_required', [], $request);

            return response()->json([
                'message' => 'Multi-factor authentication is required',
                'mfa_required' => true,
                'challenge_token' => $this->mfaChallenges->create($user),
                'available_methods' => $user->getMfaMethods(),
            ], 202);
        }

        // Generate new access token
        $tokenResult = $user->createToken('API Access Token', ['openid', 'profile', 'email']);
        $token = $tokenResult->token;

        return response()->json([
            'message' => 'Password has been reset successfully. All previous sessions have been terminated.',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ],
            'token' => [
                'access_token' => $tokenResult->accessToken,
                'token_type' => 'Bearer',
                'expires_at' => $token->expires_at,
            ],
        ]);
    }

    private function dummyTokenHash(): string
    {
        return Cache::rememberForever(
            'password_reset_dummy_hash:'.config('hashing.bcrypt.rounds'),
            fn () => Hash::make(Str::random(64))
        );
    }
}
