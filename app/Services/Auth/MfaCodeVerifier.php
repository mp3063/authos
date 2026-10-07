<?php

namespace App\Services\Auth;

use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Log;
use PragmaRX\Google2FA\Google2FA;

class MfaCodeVerifier
{
    /**
     * Verify TOTP code against user's secret
     */
    public function verifyTotpCode(User $user, string $code): bool
    {
        if (! $user->two_factor_secret) {
            return false;
        }

        try {
            $google2fa = new Google2FA;
            $secretKey = decrypt($user->two_factor_secret);

            // Verify with ±1 window for clock drift tolerance
            return $google2fa->verifyKey($secretKey, $code, 1);
        } catch (Exception $e) {
            // Log decryption or verification errors
            Log::error('MFA TOTP verification error', [
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Verify recovery code and remove it from available codes (single-use enforcement)
     */
    public function verifyAndConsumeRecoveryCode(User $user, string $code): bool
    {
        if (! $user->two_factor_recovery_codes) {
            return false;
        }

        try {
            // Get current recovery codes (already decoded as array by User model cast)
            $recoveryCodes = $user->two_factor_recovery_codes;

            if (! is_array($recoveryCodes) || empty($recoveryCodes)) {
                return false;
            }

            // Normalize input code (uppercase, trim)
            $normalizedCode = strtoupper(trim($code));

            // Use timing-safe comparison to prevent timing attacks
            $found = false;
            $foundIndex = null;

            foreach ($recoveryCodes as $index => $storedCode) {
                // Normalize stored code for comparison (case-insensitive)
                $normalizedStoredCode = strtoupper(trim($storedCode));
                if (hash_equals($normalizedStoredCode, $normalizedCode)) {
                    $found = true;
                    $foundIndex = $index;
                    break;
                }
            }

            if (! $found) {
                return false;
            }

            // Remove the used code (single-use enforcement)
            unset($recoveryCodes[$foundIndex]);
            $recoveryCodes = array_values($recoveryCodes); // Re-index array

            // Update user with remaining codes (User model mutator handles JSON encoding)
            $user->update([
                'two_factor_recovery_codes' => $recoveryCodes,
            ]);

            return true;
        } catch (Exception $e) {
            Log::error('MFA recovery code verification error', [
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }
}
