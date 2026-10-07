<?php

namespace App\Http\Controllers\Api\SSO;

use App\Http\Controllers\Controller;
use App\Services\SSO\OidcFlowService;
use App\Services\SSO\SsoSessionManager;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SsoSessionController extends Controller
{
    public function __construct(
        protected SsoSessionManager $sessions,
        protected OidcFlowService $oidcFlow,
    ) {}

    /**
     * Get user's active SSO sessions
     */
    public function sessions(Request $request): JsonResponse
    {
        try {
            $sessions = $this->sessions->getUserActiveSessions($request->user()->id);

            return response()->json([
                'success' => true,
                'data' => $sessions->map(function ($session) {
                    return [
                        'id' => $session->id,
                        'session_token' => $session->session_token,
                        'application' => [
                            'id' => $session->application->id,
                            'name' => $session->application->name,
                        ],
                        'ip_address' => $session->ip_address,
                        'user_agent' => $session->user_agent,
                        'created_at' => $session->created_at->toISOString(),
                        'last_activity_at' => $session->last_activity_at->toISOString(),
                        'expires_at' => $session->expires_at->toISOString(),
                    ];
                }),
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Revoke all user sessions
     */
    public function revokeSessions(Request $request): JsonResponse
    {
        try {
            $revokedCount = $this->sessions->revokeUserSessions($request->user()->id);

            return response()->json([
                'success' => true,
                'message' => 'All sessions revoked successfully',
                'data' => [
                    'revoked_sessions' => $revokedCount,
                ],
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Validate specific SSO session
     */
    public function validateSpecificSession(Request $request, string $sessionToken): JsonResponse
    {
        try {
            $session = $this->sessions->validateSSOSession($sessionToken);

            if (! $session) {
                return response()->json([
                    'valid' => false,
                    'error' => 'Session has expired',
                ], 400);
            }

            // Check if user owns this session
            if ($session->user_id !== $request->user()->id) {
                return response()->json([
                    'message' => 'Insufficient permissions',
                ], 403);
            }

            return response()->json([
                'valid' => true,
                'session' => [
                    'id' => $session->id,
                    'session_token' => $session->session_token,
                    'user_id' => $session->user_id,
                    'application_id' => $session->application_id,
                    'expires_at' => $session->expires_at->toISOString(),
                    'last_activity_at' => $session->last_activity_at->toISOString(),
                ],
                'user' => [
                    'id' => $session->user->id,
                    'name' => $session->user->name,
                    'email' => $session->user->email,
                ],
            ]);

        } catch (Exception $e) {
            return response()->json([
                'valid' => false,
                'error' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Refresh specific SSO session
     */
    public function refreshSpecificSession(Request $request, string $sessionToken): JsonResponse
    {
        try {
            $session = $this->sessions->validateSSOSession($sessionToken);

            if (! $session) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid or expired session token',
                ], 401);
            }

            // Check if user owns this session
            if ($session->user_id !== $request->user()->id) {
                return response()->json([
                    'message' => 'Insufficient permissions',
                ], 403);
            }

            $result = $this->oidcFlow->refreshSSOToken($sessionToken);

            return response()->json([
                'success' => true,
                'access_token' => $result['access_token'],
                'expires_at' => $result['expires_at'],
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Logout specific SSO session
     */
    public function logoutSpecificSession(Request $request, string $sessionToken): JsonResponse
    {
        try {
            $session = $this->sessions->validateSSOSession($sessionToken);

            if (! $session) {
                return response()->json([
                    'message' => 'Invalid or expired session token',
                ], 400);
            }

            // Check if user owns this session
            if ($session->user_id !== $request->user()->id) {
                return response()->json([
                    'message' => 'Insufficient permissions',
                ], 403);
            }

            $success = $this->sessions->revokeSSOSession($sessionToken, $request->user()->id);

            if ($success) {
                return response()->json([
                    'message' => 'SSO session logged out successfully',
                ]);
            } else {
                return response()->json([
                    'message' => 'Failed to logout session',
                ], 400);
            }

        } catch (Exception $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Synchronized logout - revokes all user sessions
     */
    public function synchronizedLogout(Request $request): JsonResponse
    {
        try {
            $revokedCount = $this->sessions->revokeUserSessions($request->user()->id);

            return response()->json([
                'message' => 'All SSO sessions logged out successfully',
                'revoked_count' => $revokedCount,
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 400);
        }
    }
}
