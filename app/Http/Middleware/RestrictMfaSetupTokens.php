<?php

namespace App\Http\Middleware;

use App\Services\Auth\MfaSetupTokenIssuer;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RestrictMfaSetupTokens
{
    private const ALLOWED_ROUTES = [
        'api.mfa.status',
        'api.mfa.setup',
        'api.mfa.setup.totp',
        'api.mfa.enable',
        'api.mfa.verify.totp',
        'api.auth.logout',
    ];

    public function __construct(private MfaSetupTokenIssuer $issuer) {}

    /**
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->user('api')?->token();

        if (! $this->issuer->isSetupToken($token)) {
            return $next($request);
        }

        if ($token->created_at === null || $token->created_at->lt(now()->subSeconds(MfaSetupTokenIssuer::LIFETIME_SECONDS))) {
            return response()->json([
                'error' => 'setup_token_expired',
                'error_description' => 'The MFA setup token has expired. Sign in again.',
            ], 401);
        }

        if (! in_array($request->route()?->getName(), self::ALLOWED_ROUTES, true)) {
            return response()->json([
                'error' => 'mfa_setup_required',
                'error_description' => 'Set up multi-factor authentication before using this token elsewhere.',
            ], 403);
        }

        return $next($request);
    }
}
