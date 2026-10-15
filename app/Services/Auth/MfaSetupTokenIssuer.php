<?php

namespace App\Services\Auth;

use App\Models\User;
use Laravel\Passport\AccessToken;
use Laravel\Passport\Contracts\ScopeAuthorizable;

class MfaSetupTokenIssuer
{
    public const SCOPE = 'mfa.setup';

    public const LIFETIME_SECONDS = 900;

    /**
     * @return array{setup_token: string, token_type: string, expires_in: int}
     */
    public function issue(User $user): array
    {
        return [
            'setup_token' => $user->createToken('MFA Setup Token', [self::SCOPE])->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => self::LIFETIME_SECONDS,
        ];
    }

    public function isSetupToken(?ScopeAuthorizable $token): bool
    {
        return $token instanceof AccessToken && $token->oauth_scopes === [self::SCOPE];
    }
}
