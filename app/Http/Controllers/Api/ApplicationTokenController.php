<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Api\Traits\FindsOrgScopedApplications;
use App\Models\User;
use App\Services\AuthenticationLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller as BaseController;
use Laravel\Passport\Token;

class ApplicationTokenController extends BaseController
{
    use ApiControllerHelpers;
    use FindsOrgScopedApplications;

    public function __construct(protected AuthenticationLogService $authLogService)
    {
        $this->middleware('auth:api');
    }

    /**
     * Get application active tokens
     */
    public function tokens(string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $application = $this->findApplicationWithOrgScope($id);
        $tokens = Token::where('client_id', $application->passport_client_id)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->get();

        $userIds = $tokens->pluck('user_id')->filter()->unique()->values();
        $users = User::whereIn('id', $userIds)->get()->keyBy('id');

        return response()->json([
            'data' => $tokens->map(function ($token) use ($users) {
                $user = $users->get($token->user_id);

                return [
                    'id' => $token->id,
                    'name' => $token->name,
                    'scopes' => $token->scopes,
                    'user' => $user ? [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                    ] : null,
                    'created_at' => $token->created_at,
                    'expires_at' => $token->expires_at,
                ];
            }),
        ]);
    }

    /**
     * Revoke all application tokens
     */
    public function revokeAllTokens(string $id): JsonResponse
    {
        $this->authorize('applications.update');

        $application = $this->findApplicationWithOrgScope($id);
        $revokedCount = Token::where('client_id', $application->passport_client_id)->count();

        Token::where('client_id', $application->passport_client_id)->delete();

        return response()->json([
            'message' => "Revoked $revokedCount active tokens",
        ]);
    }

    /**
     * Revoke specific application token
     */
    public function revokeToken(string $id, string $tokenId): JsonResponse
    {
        $this->authorize('applications.update');

        $application = $this->findApplicationWithOrgScope($id);
        $token = Token::where('client_id', $application->passport_client_id)
            ->where('id', $tokenId)
            ->first();

        if (! $token) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'Token not found.',
            ], 404);
        }

        // Log the token revocation
        if ($token->user) {
            $this->authLogService->logAuthenticationEvent($token->user, 'token_revoked', [
                'token_id' => $token->id,
                'application_id' => $application->id,
            ]);
        }

        // Revoke the token using Passport
        $token->revoke();

        // Also revoke refresh token if it exists
        if ($token->refreshToken) {
            $token->refreshToken->revoke();
        }

        return response()->json([
            'message' => 'Token revoked successfully',
        ]);
    }
}
