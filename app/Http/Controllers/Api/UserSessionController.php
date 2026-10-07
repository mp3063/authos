<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Models\User;
use App\Services\UserSessionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class UserSessionController extends BaseController
{
    use ApiControllerHelpers;

    public function __construct(protected UserSessionService $userSessionService)
    {
        $this->middleware('auth:api');
    }

    /**
     * Get user's active sessions
     */
    public function sessions(Request $request, string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        // Check authorization - users can view their own sessions, admins can view any
        $currentUser = auth()->user();
        if ($user->id !== $currentUser->id && ! $currentUser->hasRole(['Super Admin', 'Organization Admin'])) {
            return $this->errorResponse('Forbidden', 403);
        }

        // Get paginated sessions
        $perPage = $request->input('per_page', 15);
        $page = $request->input('page', 1);

        $query = $user->tokens()->where('revoked', false)->orderBy('created_at', 'desc');

        // Check if pagination is requested
        if ($request->has('per_page') || $request->has('page')) {
            $tokens = $query->paginate($perPage, ['*'], 'page', $page);
            $formattedSessions = $this->userSessionService->formatUserSessionsResponse($tokens->getCollection());

            return response()->json([
                'success' => true,
                'data' => $formattedSessions,
                'meta' => [
                    'current_page' => $tokens->currentPage(),
                    'per_page' => $tokens->perPage(),
                    'total' => $tokens->total(),
                    'last_page' => $tokens->lastPage(),
                ],
            ]);
        }

        $sessions = $query->get();
        $formattedSessions = $this->userSessionService->formatUserSessionsResponse($sessions);

        return response()->json([
            'success' => true,
            'data' => $formattedSessions,
        ]);
    }

    /**
     * Show specific session details
     */
    public function showSession(string $id, string $sessionId): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        // Check authorization - users can view their own sessions, admins can view any
        $currentUser = auth()->user();
        if ($user->id !== $currentUser->id && ! $currentUser->hasRole(['Super Admin', 'Organization Admin'])) {
            return $this->errorResponse('Forbidden', 403);
        }

        // Find the specific token
        $token = $user->tokens()->where('id', $sessionId)->first();

        if (! $token) {
            return $this->notFoundResponse('Session not found');
        }

        // Format the token data
        $scopes = $token->scopes;
        if (is_string($scopes)) {
            $scopes = json_decode($scopes, true) ?? [];
        }

        $sessionData = [
            'id' => $token->id,
            'name' => $token->name,
            'scopes' => $scopes ?? [],
            'created_at' => $token->created_at?->toISOString(),
            'expires_at' => $token->expires_at?->toISOString(),
            'last_used_at' => $token->updated_at?->toISOString(),
            'revoked' => (bool) $token->revoked,
        ];

        return $this->successResponse($sessionData);
    }

    /**
     * Revoke all user sessions
     */
    public function revokeSessions(string $id): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $this->userSessionService->revokeAllUserSessions($user);

        return $this->successResponse([], 'All other sessions revoked successfully');
    }

    /**
     * Revoke specific user session
     */
    public function revokeSession(string $id, string $sessionId): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $revoked = $this->userSessionService->revokeUserSession($user, $sessionId);

        if (! $revoked) {
            return $this->errorResponse('Session not found.', 404);
        }

        return $this->successResponse([], 'Session revoked successfully');
    }
}
