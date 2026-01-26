<?php

namespace App\Listeners\Auth;

use App\Models\FailedLoginAttempt;
use Illuminate\Support\Facades\Log;

/**
 * Record failed login attempts for security analysis
 *
 * This listener stores detailed information about failed login attempts
 * which is used by intrusion detection and account lockout systems.
 */
class RecordFailedLoginAttempt
{
    /**
     * Handle the event
     *
     * Note: Event parameter is not type-hinted to prevent Laravel's auto-discovery.
     * This listener is explicitly registered in EventServiceProvider with guaranteed order.
     */
    public function handle($event): void
    {
        FailedLoginAttempt::create([
            'email' => $event->email,
            'ip_address' => $event->ipAddress,
            'user_agent' => $event->userAgent,
            'attempt_type' => 'password',
            'failure_reason' => $event->reason,
            'attempted_at' => now(),
            'metadata' => array_merge($event->metadata, [
                'client_id' => $event->clientId,
                'user_id' => $event->user?->id,
            ]),
        ]);

        Log::channel('security')->info('Failed login attempt recorded', [
            'email' => $event->email,
            'ip_address' => $event->ipAddress,
            'reason' => $event->reason,
            'user_exists' => $event->user !== null,
        ]);
    }
}
