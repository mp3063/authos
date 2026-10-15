<?php

namespace App\Services\Auth;

use App\Models\User;
use Exception;
use Illuminate\Support\Facades\DB;
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
        try {
            $consumed = DB::transaction(function () use ($user, $code): bool {
                $locked = User::query()->lockForUpdate()->find($user->getKey());

                if (! $locked || ! $locked->two_factor_recovery_codes) {
                    return false;
                }

                $recoveryCodes = $locked->mfa_backup_codes;

                if (! is_array($recoveryCodes) || empty($recoveryCodes)) {
                    return false;
                }

                $normalizedCode = strtoupper(trim($code));
                $foundIndex = null;

                foreach ($recoveryCodes as $index => $storedCode) {
                    if (hash_equals(strtoupper(trim($storedCode)), $normalizedCode)) {
                        $foundIndex = $index;
                        break;
                    }
                }

                if ($foundIndex === null) {
                    return false;
                }

                unset($recoveryCodes[$foundIndex]);

                $locked->update([
                    'two_factor_recovery_codes' => array_values($recoveryCodes),
                ]);

                return true;
            });

            $user->refresh();

            return $consumed;
        } catch (Exception $e) {
            Log::error('MFA recovery code verification error', [
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }
}
