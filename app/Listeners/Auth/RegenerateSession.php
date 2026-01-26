<?php

namespace App\Listeners\Auth;

use App\Events\Auth\LoginSuccessful;
use App\Services\Security\AccountLockoutService;
use Illuminate\Support\Facades\Log;

/**
 * Perform post-login security actions
 *
 * This listener handles security tasks after successful authentication:
 * - Clear failed login attempts for the user
 * - Auto-unlock account if it was temporarily locked
 * - Log successful authentication
 */
class RegenerateSession
{
    /**
     * Create the event listener
     */
    public function __construct(
        protected AccountLockoutService $lockoutService
    ) {}

    /**
     * Handle the event
     */
    public function handle(LoginSuccessful $event): void
    {
        // Clear failed login attempts for successful login
        $this->lockoutService->clearFailedAttempts($event->user->email);

        // If there was an active lockout, unlock it (expired or overridden)
        if ($this->lockoutService->isAccountLocked($event->user->email)) {
            $this->lockoutService->unlockAccount($event->user->email, 'successful_login');

            Log::channel('security')->info('Account unlocked due to successful login', [
                'user_id' => $event->user->id,
                'email' => $event->user->email,
                'ip_address' => $event->ipAddress,
            ]);
        }

        Log::channel('security')->info('Successful login - security cleanup completed', [
            'user_id' => $event->user->id,
            'email' => $event->user->email,
            'ip_address' => $event->ipAddress,
            'client_id' => $event->clientId,
            'scopes' => $event->scopes,
        ]);
    }
}
