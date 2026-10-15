<?php

namespace App\Listeners\Auth;

use App\Models\User;
use App\Services\Auth\MfaEnforcementRevoker;
use Illuminate\Auth\Events\PasswordReset;

class EndSessionsOnPasswordReset
{
    public function __construct(private MfaEnforcementRevoker $revoker) {}

    public function handle(PasswordReset $event): void
    {
        $user = $event->user;

        if (! $user instanceof User) {
            return;
        }

        $user->forceFill(['password_changed_at' => now()])->save();
        $this->revoker->revokeAllForUser($user);
    }
}
