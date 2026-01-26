<?php

namespace App\Listeners\Auth;

use App\Events\Auth\LoginAttempted;
use App\Services\Security\IpBlocklistService;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Log;

/**
 * Check if the IP address is blocked before allowing login
 *
 * This listener runs BEFORE credential verification to abort
 * the login process if the IP is on the blocklist.
 */
class CheckIpBlocklist
{
    /**
     * Create the event listener
     */
    public function __construct(
        protected IpBlocklistService $ipBlocklistService
    ) {}

    /**
     * Handle the event
     *
     * @throws HttpResponseException If IP is blocked
     */
    public function handle(LoginAttempted $event): void
    {
        if ($this->ipBlocklistService->isIpBlocked($event->ipAddress)) {
            $blockDetails = $this->ipBlocklistService->getBlockDetails($event->ipAddress);

            Log::channel('security')->warning('Blocked IP attempted login', [
                'ip_address' => $event->ipAddress,
                'email' => $event->email,
                'block_type' => $blockDetails?->block_type,
                'block_reason' => $blockDetails?->reason,
                'blocked_at' => $blockDetails?->blocked_at,
            ]);

            throw new HttpResponseException(
                response()->json([
                    'message' => 'Access denied',
                    'error' => 'ip_blocked',
                    'error_description' => 'Your IP address has been blocked due to suspicious activity.',
                ], 403)
            );
        }
    }
}
