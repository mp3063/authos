<?php

namespace App\Listeners\Auth;

use App\Events\Auth\LoginFailed;
use App\Services\Security\AccountLockoutService;
use App\Services\Security\IntrusionDetectionService;
use Illuminate\Support\Facades\Log;

/**
 * Trigger intrusion detection checks after failed login
 *
 * This listener analyzes failed login patterns to detect:
 * - Brute force attacks (multiple attempts on same email)
 * - Credential stuffing (multiple emails from same IP)
 * - Suspicious patterns
 *
 * It automatically applies countermeasures like IP blocking
 * and progressive account lockout.
 */
class TriggerIntrusionDetection
{
    /**
     * Create the event listener
     */
    public function __construct(
        protected IntrusionDetectionService $intrusionService,
        protected AccountLockoutService $lockoutService
    ) {
    }

    /**
     * Handle the event
     *
     * Note: Event parameter is not type-hinted to prevent Laravel's auto-discovery.
     * This listener is explicitly registered in EventServiceProvider with guaranteed order.
     */
    public function handle($event): void
    {
        // Detect brute force attacks (multiple attempts on same email or IP)
        $bruteForceDetected = $this->intrusionService->detectBruteForce(
            $event->email,
            $event->ipAddress
        );

        // Detect credential stuffing (many different emails from same IP)
        $credentialStuffingDetected = $this->intrusionService->detectCredentialStuffing(
            $event->ipAddress
        );

        // Check if account should be locked based on failed attempts
        $lockout = $this->lockoutService->checkAndApplyLockout(
            $event->email,
            $event->ipAddress
        );

        if ($lockout) {
            Log::channel('security')->warning('Account locked due to failed login attempts', [
                'email' => $event->email,
                'ip_address' => $event->ipAddress,
                'attempt_count' => $lockout->attempt_count,
                'lockout_type' => $lockout->lockout_type,
                'unlock_at' => $lockout->unlock_at,
            ]);
        }

        if ($bruteForceDetected) {
            Log::channel('security')->alert('Brute force attack detected', [
                'email' => $event->email,
                'ip_address' => $event->ipAddress,
            ]);
        }

        if ($credentialStuffingDetected) {
            Log::channel('security')->critical('Credential stuffing attack detected', [
                'ip_address' => $event->ipAddress,
            ]);
        }
    }
}
