<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\Client;

class OAuthController extends Controller
{
    protected OAuthService $oAuthService;

    public function __construct(OAuthService $oAuthService)
    {
        $this->oAuthService = $oAuthService;
    }

    /**
     * OAuth 2.0 Authorization endpoint
     * GET /oauth/authorize
     */
    public function authorize(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'response_type' => 'required|string|in:code,token',
            'client_id' => 'required|string',
            'redirect_uri' => 'required|url',
            'scope' => 'sometimes|string',
            'state' => 'sometimes|string',
            'code_challenge' => 'sometimes|string',
            'code_challenge_method' => 'sometimes|string|in:S256,plain',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // Validate client
        $client = $this->oAuthService->validateClient($request->client_id);
        if (!$client) {
            return response()->json([
                'error' => 'invalid_client',
                'error_description' => 'Client authentication failed',
            ], 401);
        }

        // Validate redirect URI
        if (!$this->oAuthService->validateRedirectUri($client, $request->redirect_uri)) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => 'Invalid redirect URI',
            ], 400);
        }

        // Parse scopes
        $scopes = $request->scope ? explode(' ', $request->scope) : ['openid'];
        
        // Validate PKCE if provided
        if ($request->filled('code_challenge')) {
            if (!$this->oAuthService->clientSupportsPKCE($client)) {
                return response()->json([
                    'error' => 'invalid_request',
                    'error_description' => 'PKCE not supported for this client',
                ], 400);
            }
        }

        // Check if user is authenticated
        if (!Auth::check()) {
            return response()->json([
                'error' => 'login_required',
                'error_description' => 'User authentication required',
                'login_url' => route('login'),
            ], 401);
        }

        $user = Auth::user();

        // Generate authorization code for authorization code flow
        if ($request->response_type === 'code') {
            $authCode = $this->oAuthService->generateAuthorizationCode(
                $client,
                $user,
                $scopes,
                $request->redirect_uri,
                $request->state,
                $request->code_challenge,
                $request->code_challenge_method
            );

            $this->oAuthService->logAuthenticationEvent(
                $user,
                'oauth_authorization',
                $request,
                $client->id
            );

            $params = [
                'code' => $authCode,
            ];

            if ($request->filled('state')) {
                $params['state'] = $request->state;
            }

            return response()->json([
                'redirect_uri' => $request->redirect_uri . '?' . http_build_query($params),
            ]);
        }

        // Implicit flow (not recommended, but supported)
        if ($request->response_type === 'token') {
            $token = $this->oAuthService->generateAccessToken($user, $scopes);

            $this->oAuthService->logAuthenticationEvent(
                $user,
                'oauth_implicit_grant',
                $request,
                $client->id
            );

            $params = [
                'access_token' => $token->accessToken,
                'token_type' => 'Bearer',
                'expires_in' => $token->token->expires_at->diffInSeconds(now()),
                'scope' => implode(' ', $scopes),
            ];

            if ($request->filled('state')) {
                $params['state'] = $request->state;
            }

            return response()->json([
                'redirect_uri' => $request->redirect_uri . '#' . http_build_query($params),
            ]);
        }

        return response()->json([
            'error' => 'unsupported_response_type',
            'error_description' => 'The authorization server does not support this response type',
        ], 400);
    }

    /**
     * OAuth 2.0 Token endpoint
     * POST /oauth/token
     */
    public function token(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'grant_type' => 'required|string|in:authorization_code,refresh_token,client_credentials,password',
            'client_id' => 'required|string',
            'client_secret' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // Validate client credentials
        $client = $this->oAuthService->validateClient(
            $request->client_id,
            $request->client_secret
        );

        if (!$client) {
            return response()->json([
                'error' => 'invalid_client',
                'error_description' => 'Client authentication failed',
            ], 401);
        }

        return match ($request->grant_type) {
            'authorization_code' => $this->handleAuthorizationCodeGrant($request, $client),
            'refresh_token' => $this->handleRefreshTokenGrant($request, $client),
            'client_credentials' => $this->handleClientCredentialsGrant($request, $client),
            'password' => $this->handlePasswordGrant($request, $client),
            default => response()->json([
                'error' => 'unsupported_grant_type',
                'error_description' => 'The authorization server does not support this grant type',
            ], 400)
        };
    }

    /**
     * Handle authorization code grant
     */
    protected function handleAuthorizationCodeGrant(Request $request, Client $client): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string',
            'redirect_uri' => 'required|url',
            'code_verifier' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // This is a simplified implementation
        // In a real implementation, you would validate the authorization code
        // and exchange it for an access token
        
        return response()->json([
            'error' => 'server_error',
            'error_description' => 'Authorization code grant not fully implemented yet',
        ], 500);
    }

    /**
     * Handle refresh token grant
     */
    protected function handleRefreshTokenGrant(Request $request, Client $client): JsonResponse
    {
        return response()->json([
            'error' => 'server_error',
            'error_description' => 'Refresh token grant not implemented yet',
        ], 500);
    }

    /**
     * Handle client credentials grant
     */
    protected function handleClientCredentialsGrant(Request $request, Client $client): JsonResponse
    {
        // Generate a client credentials token
        $scopes = $request->scope ? explode(' ', $request->scope) : ['read'];
        
        return response()->json([
            'access_token' => 'client_credentials_token_placeholder',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => implode(' ', $scopes),
        ]);
    }

    /**
     * Handle password grant (Resource Owner Password Credentials)
     */
    protected function handlePasswordGrant(Request $request, Client $client): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // This would integrate with Laravel Passport's password grant
        // For now, delegate to the auth login endpoint
        return response()->json([
            'error' => 'server_error',
            'error_description' => 'Password grant should use /api/auth/login endpoint',
        ], 500);
    }
}