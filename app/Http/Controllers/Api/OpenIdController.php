<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;

class OpenIdController extends Controller
{
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
            'userinfo_endpoint' => $baseUrl.'/api/v1/oauth/userinfo',
            'jwks_uri' => $baseUrl.'/api/v1/oauth/jwks',
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
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256', 'plain'],
            'grant_types_supported' => [
                'authorization_code',
                'refresh_token',
                'client_credentials',
            ],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_post',
                'client_secret_basic',
            ],
            'claims_supported' => [
                'sub',
                'name',
                'preferred_username',
                'email',
                'email_verified',
                'picture',
                'updated_at',
                'organization_id',
                'organization_name',
            ],
        ]);
    }

    /**
     * UserInfo endpoint for OpenID Connect
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

        // Build userinfo response based on OAuth scopes
        $userInfo = [
            'sub' => (string) $user->id,
        ];

        // Use Laravel Passport's built-in scope checking
        // Add profile information if 'profile' scope is present
        if ($request->user()->tokenCan('profile')) {
            $userInfo['name'] = $user->name;
            $userInfo['preferred_username'] = $user->email;
            $userInfo['picture'] = is_array($user->profile) ? ($user->profile['avatar'] ?? null) : null;
            $userInfo['updated_at'] = $user->updated_at?->timestamp;
        }

        // Add email information if 'email' scope is present
        if ($request->user()->tokenCan('email')) {
            $userInfo['email'] = $user->email;
            $userInfo['email_verified'] = ! is_null($user->email_verified_at);
        }

        // Add organization context
        if ($user->organization) {
            $userInfo['organization_id'] = $user->organization->id;
            $userInfo['organization_name'] = $user->organization->name;
        }

        return response()->json($userInfo);
    }

    /**
     * JSON Web Key Set (JWKS) endpoint
     * GET /oauth/jwks
     */
    public function jwks(): JsonResponse
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
        $publicKeyResource = openssl_pkey_get_public($publicKey);

        if ($publicKeyResource === false) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => 'Invalid public key format',
            ], 500);
        }

        $keyDetails = openssl_pkey_get_details($publicKeyResource);

        if (! $keyDetails || $keyDetails['type'] !== OPENSSL_KEYTYPE_RSA) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => 'Invalid key format',
            ], 500);
        }

        // Convert RSA key parameters to JWK format
        $n = $this->base64UrlEncode($keyDetails['rsa']['n']);
        $e = $this->base64UrlEncode($keyDetails['rsa']['e']);

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
     * Base64 URL encode helper
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
