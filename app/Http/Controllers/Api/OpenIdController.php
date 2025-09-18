<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;

class OpenIdController extends Controller
{
    protected OAuthService $oAuthService;

    public function __construct(OAuthService $oAuthService)
    {
        $this->oAuthService = $oAuthService;
    }

    /**
     * OpenID Connect Discovery endpoint
     * GET /.well-known/openid-configuration
     */
    public function discovery(Request $request): JsonResponse
    {
        $baseUrl = $request->getSchemeAndHttpHost();

        return response()->json([
            'issuer' => $baseUrl,
            'authorization_endpoint' => $baseUrl.'/oauth/authorize',
            'token_endpoint' => $baseUrl.'/oauth/token',
            'userinfo_endpoint' => $baseUrl.'/oauth/userinfo',
            'jwks_uri' => $baseUrl.'/oauth/jwks',
            'scopes_supported' => [
                'openid',
                'profile',
                'email',
                'read',
                'write',
            ],
            'response_types_supported' => [
                'code',
                'token',
                'id_token',
                'code token',
                'code id_token',
                'token id_token',
                'code token id_token',
            ],
            'grant_types_supported' => [
                'authorization_code',
                'implicit',
                'refresh_token',
                'client_credentials',
                'password',
            ],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_basic',
                'client_secret_post',
            ],
            'claims_supported' => [
                'sub',
                'name',
                'given_name',
                'family_name',
                'preferred_username',
                'email',
                'email_verified',
                'picture',
                'updated_at',
            ],
            'code_challenge_methods_supported' => ['S256', 'plain'],
        ]);
    }

    /**
     * JSON Web Key Set (JWKS) endpoint
     * GET /oauth/jwks
     */
    public function jwks(Request $request): JsonResponse
    {
        // Read the public key
        $publicKeyPath = storage_path('oauth-public.key');

        if (! File::exists($publicKeyPath)) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => 'Public key not found',
            ], 500);
        }

        $publicKey = File::get($publicKeyPath);

        // Parse the public key to extract parameters
        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));

        if (! $keyDetails || $keyDetails['type'] !== OPENSSL_KEYTYPE_RSA) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => 'Invalid key format',
            ], 500);
        }

        // Convert RSA key parameters to JWK format
        $n = base64url_encode($keyDetails['rsa']['n']);
        $e = base64url_encode($keyDetails['rsa']['e']);

        return response()->json([
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'kid' => 'authos-'.md5($publicKey),
                    'n' => $n,
                    'e' => $e,
                    'alg' => 'RS256',
                ],
            ],
        ]);
    }

    /**
     * UserInfo endpoint
     * GET /oauth/userinfo
     */
    public function userinfo(Request $request): JsonResponse
    {
        $user = Auth::guard('api')->user();

        if (! $user) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => 'The access token provided is invalid',
            ], 401);
        }

        // Get token scopes - handle both testing and production scenarios
        $scopes = $this->getTokenScopes($request, $user);

        $userInfo = $this->oAuthService->getUserInfo($user, $scopes);

        return response()->json($userInfo);
    }

    /**
     * Get the current token's scopes
     */
    protected function getTokenScopes(Request $request, $user): array
    {
        // Priority 1: If Bearer token present, decode JWT first (most accurate for OAuth flows)
        if ($request->bearerToken()) {
            $bearerToken = $request->bearerToken();

            // Check if it's a JWT token (contains 3 parts separated by dots)
            if (substr_count($bearerToken, '.') === 2) {
                try {
                    // Decode JWT payload (middle part)
                    $parts = explode('.', $bearerToken);
                    $payload = json_decode(base64_decode($parts[1]), true);

                    if (isset($payload['scopes']) && ! empty($payload['scopes'])) {
                        return $payload['scopes'];
                    }
                } catch (\Exception $e) {
                    // JWT decoding failed, continue to other methods
                }
            } else {
                // Try database lookup for non-JWT tokens
                $dbToken = \Laravel\Passport\Token::find($bearerToken);
                if ($dbToken && isset($dbToken->scopes) && ! empty($dbToken->scopes)) {
                    return $dbToken->scopes;
                }
            }
        }

        // Priority 2: Get token from user object (works with Passport::actingAs)
        $token = $user->token() ?: $user->currentAccessToken();

        if ($token) {
            // For Laravel\Passport\AccessToken objects, access oauth_scopes directly
            if (isset($token->oauth_scopes) && ! empty($token->oauth_scopes) && $token->oauth_scopes !== ['*']) {
                return $token->oauth_scopes;
            }

            // Check if it's an AccessToken object with oauth_scopes in attributes
            if (isset($token->attributes['oauth_scopes'])) {
                return $token->attributes['oauth_scopes'];
            }

            // Check for regular database tokens
            if (isset($token->scopes) && ! empty($token->scopes)) {
                return $token->scopes;
            }
        }

        // Priority 3: Try accessing the accessToken property directly (Passport::actingAs sets this)
        if (property_exists($user, 'accessToken') && $user->accessToken) {
            $accessToken = $user->accessToken;
            if (isset($accessToken->oauth_scopes)) {
                return $accessToken->oauth_scopes;
            }
            if (isset($accessToken->attributes['oauth_scopes'])) {
                return $accessToken->attributes['oauth_scopes'];
            }
        }

        // Priority 4: Fallback to request attributes
        if ($request->has('_passport_scopes')) {
            return $request->get('_passport_scopes');
        }

        // Default to only openid scope for OIDC compliance
        return ['openid'];
    }

    /**
     * Generate ID Token (JWT)
     * This would typically be called during the OAuth flow
     */
    public function generateIdToken(
        $user,
        string $clientId,
        array $scopes,
        ?string $nonce = null
    ): string {
        $privateKeyPath = storage_path('oauth-private.key');
        $privateKey = File::get($privateKeyPath);

        $header = [
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => 'authos-'.md5(File::get(storage_path('oauth-public.key'))),
        ];

        $now = time();
        $payload = [
            'iss' => request()->getSchemeAndHttpHost(),
            'sub' => (string) $user->id,
            'aud' => $clientId,
            'exp' => $now + 3600, // 1 hour
            'iat' => $now,
            'auth_time' => $now,
        ];

        if ($nonce) {
            $payload['nonce'] = $nonce;
        }

        // Add claims based on scopes
        if (in_array('profile', $scopes)) {
            $payload = array_merge($payload, [
                'name' => $user->name,
                'preferred_username' => $user->name,
                'updated_at' => $user->updated_at?->timestamp,
            ]);

            if ($user->profile) {
                $payload = array_merge($payload, [
                    'given_name' => $user->profile['first_name'] ?? null,
                    'family_name' => $user->profile['last_name'] ?? null,
                    'picture' => $user->avatar,
                ]);
            }
        }

        if (in_array('email', $scopes)) {
            $payload = array_merge($payload, [
                'email' => $user->email,
                'email_verified' => ! is_null($user->email_verified_at),
            ]);
        }

        // Remove null values
        $payload = array_filter($payload);

        // Encode header and payload
        $headerEncoded = base64url_encode(json_encode($header));
        $payloadEncoded = base64url_encode(json_encode($payload));

        // Create signature
        $signature = '';
        openssl_sign(
            $headerEncoded.'.'.$payloadEncoded,
            $signature,
            $privateKey,
            OPENSSL_ALGO_SHA256
        );

        $signatureEncoded = base64url_encode($signature);

        return $headerEncoded.'.'.$payloadEncoded.'.'.$signatureEncoded;
    }
}

// Helper function for base64url encoding
if (! function_exists('base64url_encode')) {
    function base64url_encode($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
