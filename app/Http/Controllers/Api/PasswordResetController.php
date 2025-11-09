<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\PasswordResetConfirmRequest;
use App\Http\Requests\Api\PasswordResetRequest;
use App\Models\User;
use App\Notifications\PasswordResetNotification;
use App\Services\AuthenticationLogService;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Token;

class PasswordResetController extends Controller
{
    protected AuthenticationLogService $authLogService;

    public function __construct(AuthenticationLogService $authLogService)
    {
        $this->authLogService = $authLogService;
    }

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

        // Generate cryptographically secure random token (64 characters)
        // SECURITY: Use random_bytes() instead of Str::random() for cryptographic security
        // random_bytes() uses OS-level CSPRNG (Linux: /dev/urandom, Windows: CryptGenRandom)
        try {
            $token = bin2hex(random_bytes(32)); // 32 bytes = 64 hex characters
        } catch (\Exception $e) {
            // Fallback should never happen on modern PHP installations
            // Log critical error and fail securely
            \Log::critical('Failed to generate cryptographically secure random token', [
                'error' => $e->getMessage(),
                'email' => $email,
            ]);

            return response()->json([
                'message' => 'Unable to process password reset request. Please try again later.',
                'error' => 'token_generation_failed',
            ], 500);
        }

        // Hash the token before storing (NEVER store plain tokens)
        $hashedToken = hash('sha256', $token);

        // Delete any existing tokens for this email
        DB::table('password_reset_tokens')
            ->where('email', $email)
            ->delete();

        // Store hashed token with creation timestamp
        DB::table('password_reset_tokens')->insert([
            'email' => $email,
            'token' => $hashedToken,
            'created_at' => now(),
        ]);

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

        // Hash the provided token to compare with stored hash
        $hashedToken = hash('sha256', $plainToken);

        // Find the reset token record
        $resetRecord = DB::table('password_reset_tokens')
            ->where('email', $email)
            ->first();

        // SECURITY: Constant-time token validation to prevent timing attacks
        // Always perform hash_equals() even when record doesn't exist to maintain constant time
        $dummyToken = hash('sha256', 'dummy-token-for-timing-safety-' . config('app.key'));
        $tokenToCompare = $resetRecord ? $resetRecord->token : $dummyToken;

        // SECURITY: Always parse timestamp even for non-existent records to maintain constant timing
        // This ensures both code paths perform the same Carbon operations
        $dummyTimestamp = now()->subMinutes(30)->toDateTimeString();
        $timestampToParse = $resetRecord ? $resetRecord->created_at : $dummyTimestamp;
        $tokenCreatedAt = Carbon::parse($timestampToParse);

        // Calculate token expiration time (always perform calculation for constant timing)
        $tokenExpiresAt = $tokenCreatedAt->copy()->addMinutes(60);

        // SECURITY: Compute all checks upfront to prevent timing leaks from short-circuit evaluation
        // Both valid and invalid code paths must execute the same operations
        $recordExists = (bool) $resetRecord;
        $tokenMatches = hash_equals($tokenToCompare, $hashedToken);
        $hasExpirationTime = true; // Always true since we always calculate expiration
        $notExpired = now()->lt($tokenExpiresAt);

        // Combine checks (all operations already executed, no short-circuit timing leak)
        $isValid = $recordExists && $tokenMatches && $hasExpirationTime && $notExpired;

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
                    ->where('email', 'dummy-timing-protection-' . hash('sha256', $email))
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

        // Update user password
        $user->update([
            'password' => Hash::make($newPassword),
            'password_changed_at' => now(),
        ]);

        // SECURITY: Delete token immediately after use (single-use)
        DB::table('password_reset_tokens')
            ->where('email', $email)
            ->delete();

        // SECURITY: Revoke all existing access tokens
        Token::where('user_id', $user->id)
            ->where('revoked', false)
            ->update(['revoked' => true]);

        // Log password reset success
        $this->authLogService->logAuthenticationEvent(
            $user,
            'password_reset_completed',
            ['status' => 'success'],
            $request
        );

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
}
