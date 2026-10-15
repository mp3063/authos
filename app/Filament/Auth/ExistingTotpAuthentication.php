<?php

namespace App\Filament\Auth;

use App\Models\User;
use App\Services\Auth\MfaCodeVerifier;
use Filament\Actions\Action;
use Filament\Auth\MultiFactor\App\AppAuthentication;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthenticationRecovery;
use Filament\Facades\Filament;
use Illuminate\Contracts\Auth\Authenticatable;
use SensitiveParameter;

class ExistingTotpAuthentication extends AppAuthentication
{
    protected bool $isRecoverable = true;

    public function isEnabled(Authenticatable $user): bool
    {
        return $user instanceof User && $user->hasMfaEnabled();
    }

    public function verifyCode(#[SensitiveParameter] string $code, #[SensitiveParameter] ?string $secret = null, bool $shouldPreventCodeReuse = false): bool
    {
        $secret ??= $this->getSecret(Filament::auth()->user());
        $secretHolder = new User(['two_factor_secret' => encrypt($secret)]);

        if (! app(MfaCodeVerifier::class)->verifyTotpCode($secretHolder, $code)) {
            return false;
        }

        return ! $shouldPreventCodeReuse || parent::verifyCode($code, $secret, shouldPreventCodeReuse: true);
    }

    public function verifyRecoveryCode(#[SensitiveParameter] string $recoveryCode, ?HasAppAuthenticationRecovery $user = null): bool
    {
        $user ??= Filament::auth()->user();

        return $user instanceof User && app(MfaCodeVerifier::class)->verifyAndConsumeRecoveryCode($user, $recoveryCode);
    }

    /**
     * @param  array<string> | null  $codes
     */
    public function saveRecoveryCodes(HasAppAuthenticationRecovery $user, #[SensitiveParameter] ?array $codes): void
    {
        $user->saveAppAuthenticationRecoveryCodes($codes);
    }

    /**
     * @return array<Action>
     */
    public function getActions(): array
    {
        $user = Filament::auth()->user();

        return array_map(
            fn (Action $action): Action => $action->getName() === 'disableAppAuthentication'
                ? $action->visible(fn (): bool => $this->isEnabled($user) && ! $user->organization?->requiresMfa())
                : $action,
            parent::getActions(),
        );
    }
}
