<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\SSOService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;
use Exception;

class SSOController extends Controller
{
    protected SSOService $ssoService;

    public function __construct(SSOService $ssoService)
    {
        $this->ssoService = $ssoService;
    }

    /**
     * Initiate SSO flow
     */
    public function initiate(Request $request): JsonResponse
    {
        $request->validate([
            'application_id' => 'required|integer|exists:applications,id',
            'redirect_uri' => 'required|url',
        ]);

        try {
            $result = $this->ssoService->initiateSSO(
                $request->application_id,
                $request->redirect_uri,
                $request->user(),
                $request->ip(),
                $request->userAgent()
            );

            return response()->json([
                'success' => true,
                'data' => $result,
                'redirect_url' => $request->redirect_uri . '?' . http_build_query([
                    'code' => $result['auth_code'],
                    'state' => $result['state'],
                ])
            ]);

        } catch (ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $e->errors()
            ], 422);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Handle SSO callback and exchange auth code for tokens
     */
    public function callback(Request $request): JsonResponse
    {
        $request->validate([
            'code' => 'required|string',
            'application_id' => 'required|integer|exists:applications,id',
            'redirect_uri' => 'sometimes|url',
        ]);

        try {
            $result = $this->ssoService->validateCallback(
                $request->code,
                $request->application_id,
                $request->redirect_uri
            );

            return response()->json([
                'success' => true,
                'data' => $result
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Validate SSO session token
     */
    public function validate(Request $request): JsonResponse
    {
        $request->validate([
            'token' => 'required|string',
        ]);

        try {
            $session = $this->ssoService->validateSession($request->token);

            if (!$session) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid or expired session token'
                ], 401);
            }

            return response()->json([
                'success' => true,
                'data' => [
                    'valid' => true,
                    'user' => [
                        'id' => $session->user->id,
                        'name' => $session->user->name,
                        'email' => $session->user->email,
                        'organization_id' => $session->user->organization_id,
                    ],
                    'application' => [
                        'id' => $session->application->id,
                        'name' => $session->application->name,
                    ],
                    'expires_at' => $session->expires_at->toISOString(),
                    'last_activity' => $session->last_activity_at->toISOString(),
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Refresh SSO session
     */
    public function refresh(Request $request): JsonResponse
    {
        $request->validate([
            'refresh_token' => 'required|string',
        ]);

        try {
            $result = $this->ssoService->refreshSession($request->refresh_token);

            return response()->json([
                'success' => true,
                'data' => $result
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Logout and synchronize across applications
     */
    public function logout(Request $request): JsonResponse
    {
        $request->validate([
            'token' => 'required|string',
        ]);

        try {
            $result = $this->ssoService->synchronizeLogout($request->token);

            return response()->json([
                'success' => true,
                'message' => 'Logout successful',
                'data' => $result
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Get SSO configuration for an application
     */
    public function configuration(Request $request, int $applicationId): JsonResponse
    {
        try {
            $config = $this->ssoService->getConfiguration($applicationId);

            return response()->json([
                'success' => true,
                'data' => [
                    'application_id' => $config->application_id,
                    'logout_url' => $config->logout_url,
                    'callback_url' => $config->callback_url,
                    'allowed_domains' => $config->allowed_domains,
                    'session_lifetime' => $config->session_lifetime,
                    'is_active' => $config->is_active,
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 404);
        }
    }

    /**
     * Get user's active SSO sessions
     */
    public function sessions(Request $request): JsonResponse
    {
        try {
            $sessions = $this->ssoService->getUserActiveSessions($request->user()->id);

            return response()->json([
                'success' => true,
                'data' => $sessions->map(function ($session) {
                    return [
                        'id' => $session->id,
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
                })
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Revoke all user sessions
     */
    public function revokeSessions(Request $request): JsonResponse
    {
        try {
            $revokedCount = $this->ssoService->revokeUserSessions($request->user()->id);

            return response()->json([
                'success' => true,
                'message' => 'All sessions revoked successfully',
                'data' => [
                    'revoked_sessions' => $revokedCount
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ], 400);
        }
    }
}