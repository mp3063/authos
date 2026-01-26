<?php

namespace App\Listeners\Auth;

use App\Events\Auth\LoginSuccessful;
use App\Models\AuthenticationLog;
use App\Notifications\NewDeviceLoginAlert;
use Illuminate\Support\Facades\Log;

class SendNewDeviceLoginAlert
{
    public function handle(LoginSuccessful $event): void
    {
        $user = $event->user;
        $ipAddress = $event->ipAddress;
        $userAgent = $event->userAgent ?? 'Unknown';

        // Check if this IP + user agent combination has been seen before
        $knownDevice = AuthenticationLog::where('user_id', $user->id)
            ->where('ip_address', $ipAddress)
            ->where('user_agent', $userAgent)
            ->where('event', 'login_success')
            ->exists();

        if (! $knownDevice) {
            $user->notify(new NewDeviceLoginAlert($ipAddress, $userAgent));

            Log::channel('security')->info('New device login alert sent', [
                'user_id' => $user->id,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
            ]);
        }
    }
}
