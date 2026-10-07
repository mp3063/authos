<?php

namespace App\Http\Controllers\Api;

use App\Events\MfaDisabledEvent;
use App\Events\MfaEnabledEvent;
use App\Mail\MfaSetupConfirmation;
use App\Models\User;
use App\Services\Auth\MfaCodeVerifier;
use App\Services\AuthenticationLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\Rule;
use PragmaRX\Google2FA\Google2FA;

class MfaController extends BaseController
{
    public function __construct(
        protected AuthenticationLogService $authLogService,
        protected MfaCodeVerifier $mfaCodeVerifier
    ) {
        $this->middleware('auth:api');
    }

    /**
     * Get MFA status
     */
    public function mfaStatus(): JsonResponse
    {
        $user = Auth::user();

        return response()->json([
            'data' => [
                'mfa_enabled' => $user->hasMfaEnabled(),
                'mfa_methods' => $user->mfa_methods ?? [],
                'backup_codes_count' => count($user->mfa_backup_codes ?? []),
                'totp_configured' => ! empty($user->two_factor_secret),
            ],
        ]);
    }

    /**
     * Setup TOTP for MFA
     */
    public function setupTotp(): JsonResponse
    {
        $user = Auth::user();

        if ($user->hasMfaEnabled()) {
            return response()->json([
                'success' => false,
                'error' => 'resource_conflict',
                'error_description' => 'MFA is already enabled for this account.',
            ], 409);
        }

        $google2fa = new Google2FA;

        // Generate secret key with proper length (minimum 16 characters)
        $secretKey = $google2fa->generateSecretKey(16); // Standard length for Google2FA

        // Store the secret temporarily (not confirmed yet)
        $user->update(['two_factor_secret' => encrypt($secretKey)]);

        $qrCodeUrl = $google2fa->getQRCodeUrl(
            config('app.name', 'Auth Service'),
            $user->email,
            $secretKey
        );

        return response()->json([
            'success' => true,
            'data' => [
                'secret' => $secretKey,
                'qr_code_url' => $qrCodeUrl,
                'backup_codes' => [], // Will be generated after verification
            ],
            'message' => 'TOTP setup initiated. Please verify to complete setup.',
        ]);
    }

    /**
     * Verify and enable TOTP
     */
    public function verifyTotp(Request $request): JsonResponse
    {
        $request->validate([
            'code' => 'required|string|size:6',
        ]);

        $user = Auth::user();

        if (! $user->two_factor_secret) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'TOTP setup not initiated.',
            ], 404);
        }

        $google2fa = new Google2FA;
        $secretKey = decrypt($user->two_factor_secret);

        if (! $google2fa->verifyKey($secretKey, $request->code)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Invalid TOTP code.',
            ], 401);
        }

        // Generate backup codes
        $backupCodes = $this->generateBackupCodes();

        // Enable MFA
        $user->update([
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($backupCodes),
            'two_factor_confirmed_at' => now(),
        ]);

        MfaEnabledEvent::dispatch($user);

        // Log MFA enabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_enabled',
            [],
            $request
        );

        return response()->json([
            'data' => [
                'backup_codes' => $backupCodes,
            ],
            'message' => 'TOTP enabled successfully. Please store your backup codes safely.',
        ]);
    }

    /**
     * Disable TOTP
     */
    public function disableTotp(Request $request): JsonResponse
    {
        $user = Auth::user();

        $request->validate([
            'password' => 'required|string',
            'code' => [Rule::requiredIf($user->hasMfaEnabled()), 'string'],
        ]);

        // Verify password
        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        if ($user->hasMfaEnabled() && ! $this->verifySecondFactor($user, $request->code)) {
            return $this->invalidSecondFactorResponse();
        }

        // Disable MFA
        $user->update([
            'two_factor_secret' => null,
            'mfa_methods' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ]);

        MfaDisabledEvent::dispatch($user);

        // Log MFA disabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_disabled',
            [],
            $request
        );

        return response()->json([
            'message' => 'TOTP disabled successfully.',
        ]);
    }

    /**
     * Get recovery codes
     */
    public function getRecoveryCodes(Request $request): JsonResponse
    {
        $request->validate([
            'password' => 'required|string',
        ]);

        $user = Auth::user();

        // Verify password
        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        if (! $user->hasMfaEnabled()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'MFA is not enabled.',
            ], 404);
        }

        return response()->json([
            'data' => [
                'recovery_codes' => json_decode($user->two_factor_recovery_codes, true) ?? [],
            ],
        ]);
    }

    /**
     * Regenerate recovery codes
     */
    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        $request->validate([
            'password' => 'required|string',
        ]);

        $user = Auth::user();

        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        if (! $user->hasMfaEnabled()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'MFA is not enabled.',
            ], 404);
        }

        // Generate new backup codes
        $backupCodes = $this->generateBackupCodes();

        $user->update(['two_factor_recovery_codes' => json_encode($backupCodes)]);

        // Log recovery codes regenerated
        $this->authLogService->logAuthenticationEvent(
            $user,
            'recovery_codes_regenerated',
            [],
            $request
        );

        return response()->json([
            'data' => [
                'recovery_codes' => $backupCodes,
            ],
            'message' => 'Recovery codes regenerated successfully.',
        ]);
    }

    /**
     * Enable MFA after setup
     */
    public function enableMfa(Request $request): JsonResponse
    {
        $request->validate([
            'code' => 'required|string|size:6',
        ]);

        $user = Auth::user();

        if (! $user->two_factor_secret) {
            return response()->json([
                'success' => false,
                'error' => 'resource_not_found',
                'error_description' => 'TOTP setup not initiated.',
            ], 404);
        }

        $google2fa = new Google2FA;
        $secretKey = decrypt($user->two_factor_secret);

        if (! $google2fa->verifyKey($secretKey, $request->code)) {
            return response()->json([
                'success' => false,
                'error' => 'authentication_failed',
                'error_description' => 'Invalid TOTP code.',
            ], 401);
        }

        // Generate backup codes
        $backupCodes = $this->generateBackupCodes();

        // Enable MFA
        $user->update([
            'mfa_secret' => encrypt($secretKey), // Store encrypted secret for compatibility
            'mfa_methods' => ['totp'],
            'mfa_backup_codes' => $backupCodes, // Mutator handles JSON encoding to two_factor_recovery_codes
            'two_factor_confirmed_at' => now(),
        ]);

        MfaEnabledEvent::dispatch($user);

        // Log MFA enabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_enabled',
            [],
            $request
        );

        // Send MFA setup confirmation email
        Mail::to($user)->send(new MfaSetupConfirmation($user, ['totp']));

        return response()->json([
            'success' => true,
            'data' => [
                'backup_codes' => $backupCodes,
                'mfa_enabled' => true,
                'methods' => ['totp'],
            ],
            'message' => 'MFA enabled successfully. Please store your backup codes safely.',
        ]);
    }

    /**
     * Disable MFA
     */
    public function disableMfa(Request $request): JsonResponse
    {
        $user = Auth::user();

        $request->validate([
            'password' => 'required|string',
            'code' => [Rule::requiredIf($user->hasMfaEnabled()), 'string'],
        ]);

        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        if ($user->hasMfaEnabled() && ! $this->verifySecondFactor($user, $request->code)) {
            return $this->invalidSecondFactorResponse();
        }

        // Disable MFA for the user
        $user->update([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
            'mfa_methods' => null,
        ]);

        MfaDisabledEvent::dispatch($user);

        // Log MFA disabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_disabled',
            [],
            $request
        );

        return response()->json([
            'success' => true,
            'data' => [
                'mfa_enabled' => false,
                'methods' => [],
            ],
            'message' => 'MFA disabled successfully',
        ]);
    }

    private function verifySecondFactor(User $user, ?string $code): bool
    {
        if (! $code) {
            return false;
        }

        return $this->mfaCodeVerifier->verifyTotpCode($user, $code)
            || $this->mfaCodeVerifier->verifyAndConsumeRecoveryCode($user, $code);
    }

    private function invalidSecondFactorResponse(): JsonResponse
    {
        return response()->json([
            'error' => 'authentication_failed',
            'error_description' => 'Invalid TOTP or recovery code.',
        ], 401);
    }

    /**
     * @return list<string>
     */
    private function generateBackupCodes(): array
    {
        $alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

        return array_map(
            fn (): string => implode('', array_map(fn (): string => $alphabet[random_int(0, 35)], range(1, 8))),
            range(1, 8),
        );
    }
}
