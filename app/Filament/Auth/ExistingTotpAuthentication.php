<?php

namespace App\Filament\Auth;

use App\Events\MfaEnabledEvent;
use App\Models\User;
use App\Services\Auth\MfaCodeVerifier;
use App\Services\AuthenticationLogService;
use Filament\Actions\Action;
use Filament\Auth\MultiFactor\App\AppAuthentication;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthentication;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthenticationRecovery;
use Filament\Facades\Filament;
use Illuminate\Contracts\Auth\Authenticatable;
use Livewire\Component;
use SensitiveParameter;

class ExistingTotpAuthentication extends AppAuthentication
{
    protected bool $isRecoverable = true;

    public function isEnabled(Authenticatable $user): bool
    {
        return $user instanceof User && $user->hasMfaEnabled();
    }

    public function getSecret(HasAppAuthentication $user): string
    {
        return $user->getAppAuthenticationSecret() ?? '';
    }

    public function verifyCode(#[SensitiveParameter] string $code, #[SensitiveParameter] ?string $secret = null, bool $shouldPreventCodeReuse = false): bool
    {
        $secret ??= $this->getSecret(Filament::auth()->user());

        if ($secret === '') {
            return false;
        }

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
            fn (Action $action): Action => match ($action->getName()) {
                'setUpAppAuthentication' => $action->after(fn (Component $livewire) => $this->afterSetUp($user, $livewire)),
                'disableAppAuthentication' => $action->visible(fn (): bool => $this->isEnabled($user) && ! $user->organization?->requiresMfa()),
                default => $action,
            },
            parent::getActions(),
        );
    }

    protected function afterSetUp(User $user, Component $livewire): void
    {
        if (! $this->isEnabled($user)) {
            return;
        }

        MfaEnabledEvent::dispatch($user);
        app(AuthenticationLogService::class)->logAuthenticationEvent($user, 'mfa_enabled');

        if (! $user->organization?->requiresMfa()) {
            return;
        }

        $intendedUrl = session()->pull('url.intended');
        Filament::auth()->logout();
        session()->invalidate();
        session()->regenerateToken();

        if (filled($intendedUrl)) {
            session()->put('url.intended', $intendedUrl);
        }

        $livewire->redirect(Filament::getLoginUrl());
    }
}
