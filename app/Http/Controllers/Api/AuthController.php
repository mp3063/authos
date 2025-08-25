<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;

class AuthController extends Controller
{
    protected OAuthService $oAuthService;

    public function __construct(OAuthService $oAuthService)
    {
        $this->oAuthService = $oAuthService;
    }

    /**
     * User login endpoint
     */
    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
            'client_id' => 'sometimes|string',
            'scopes' => 'sometimes|array',
            'scopes.*' => 'string|in:openid,profile,email,read,write',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            $this->oAuthService->logAuthenticationEvent(
                $user ?? new User(['email' => $request->email]),
                'login_failed',
                $request,
                $request->client_id,
                false
            );

            return response()->json([
                'error' => 'invalid_grant',
                'error_description' => 'The provided credentials are incorrect.',
            ], 401);
        }

        $scopes = $request->input('scopes', ['openid']);
        $token = $this->oAuthService->generateAccessToken($user, $scopes);

        $this->oAuthService->logAuthenticationEvent(
            $user,
            'login_success',
            $request,
            $request->client_id
        );

        return response()->json([
            'access_token' => $token->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $token->token->expires_at->diffInSeconds(now()),
            'scope' => implode(' ', $scopes),
        ]);
    }

    /**
     * User logout endpoint
     */
    public function logout(Request $request): JsonResponse
    {
        $user = Auth::guard('api')->user();
        
        if ($user) {
            $token = $user->token();
            $this->oAuthService->revokeToken($token->id);
            
            $this->oAuthService->logAuthenticationEvent(
                $user,
                'logout',
                $request
            );
        }

        return response()->json([
            'message' => 'Successfully logged out',
        ]);
    }

    /**
     * Get authenticated user info
     */
    public function user(Request $request): JsonResponse
    {
        $user = Auth::guard('api')->user();
        $token = $user->token();
        
        // Get scopes from the token
        $scopes = $token->scopes ?? ['openid'];
        
        $userInfo = $this->oAuthService->getUserInfo($user, $scopes);

        return response()->json($userInfo);
    }

    /**
     * Refresh access token
     */
    public function refresh(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => $validator->errors()->first(),
            ], 400);
        }

        // Laravel Passport handles refresh tokens automatically
        // This endpoint would integrate with Passport's token refresh logic
        
        return response()->json([
            'error' => 'unsupported_grant_type',
            'error_description' => 'Refresh token flow not yet implemented',
        ], 400);
    }

    /**
     * Revoke access token
     */
    public function revoke(Request $request): JsonResponse
    {
        $user = Auth::guard('api')->user();
        
        if ($user) {
            $token = $user->token();
            $this->oAuthService->revokeToken($token->id);
            
            $this->oAuthService->logAuthenticationEvent(
                $user,
                'token_revoked',
                $request
            );
        }

        return response()->json([
            'message' => 'Token revoked successfully',
        ]);
    }
}