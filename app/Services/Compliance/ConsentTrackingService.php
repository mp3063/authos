<?php

namespace App\Services\Compliance;

use App\Models\User;
use App\Models\UserConsent;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Request;

class ConsentTrackingService
{
    /**
     * Record (or re-record) a consent for a user. Re-recording the same type
     * supersedes any prior withdrawal — a user who withdraws and then opts back
     * in should appear as actively consented again.
     */
    public function recordConsent(
        User $user,
        string $consentType,
        ?string $termsVersion = null,
        ?string $ipAddress = null,
    ): UserConsent {
        $ipAddress ??= Request::ip();

        return UserConsent::query()
            ->updateOrCreate(
                [
                    'user_id' => $user->id,
                    'consent_type' => $consentType,
                ],
                [
                    'organization_id' => $user->organization_id,
                    'terms_version' => $termsVersion,
                    'ip_address' => $ipAddress,
                    'given_at' => CarbonImmutable::now(),
                    'withdrawn_at' => null,
                ],
            );
    }

    /**
     * Withdraw a consent. No-op if the user never gave it. Soft-mark only:
     * we keep the historical row so auditors can see the consent existed.
     */
    public function withdrawConsent(User $user, string $consentType): void
    {
        UserConsent::query()
            ->where('user_id', $user->id)
            ->where('consent_type', $consentType)
            ->whereNull('withdrawn_at')
            ->update(['withdrawn_at' => CarbonImmutable::now()]);
    }

    /**
     * Whether the user currently has an active consent of the given type.
     */
    public function hasActiveConsent(User $user, string $consentType): bool
    {
        return UserConsent::query()
            ->where('user_id', $user->id)
            ->where('consent_type', $consentType)
            ->active()
            ->exists();
    }
}
