<?php

namespace App\Listeners\Auth;

use App\Events\Auth\LoginAttempted;
use App\Services\Security\AccountLockoutService;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Log;

/**
 * Check if the account is locked before allowing login
 *
 * This listener runs BEFORE credential verification to abort
 * the login process if the account is locked.
 */
class CheckAccountLockout
{
    /**
     * Create the event listener
     */
    public function __construct(
        protected AccountLockoutService $lockoutService
    ) {
    }

    /**
     * Handle the event
     *
     * @throws HttpResponseException If account is locked
     */
    public function handle(LoginAttempted $event): void
    {
        if ($this->lockoutService->isAccountLocked($event->email)) {
            $lockout = $this->lockoutService->getActiveLockout($event->email);
            $remainingMinutes = $this->lockoutService->getRemainingLockoutTime($event->email);

            Log::channel('security')->warning('Locked account attempted login', [
                'email' => $event->email,
                'ip_address' => $event->ipAddress,
                'lockout_type' => $lockout?->lockout_type,
                'locked_at' => $lockout?->locked_at,
                'unlock_at' => $lockout?->unlock_at,
                'remaining_minutes' => $remainingMinutes,
            ]);

            $message = 'Your account has been temporarily locked due to multiple failed login attempts.';
            if ($remainingMinutes !== null && $remainingMinutes > 0) {
                $message .= " Please try again in {$remainingMinutes} minute(s).";
            }

            throw new HttpResponseException(
                response()->json([
                    'message' => $message,
                    'error' => 'account_locked',
                    'error_description' => $lockout?->reason ?? 'Account is locked',
                    'locked_until' => $lockout?->unlock_at?->toIso8601String(),
                    'remaining_minutes' => $remainingMinutes,
                ], 403)
            );
        }
    }
}
