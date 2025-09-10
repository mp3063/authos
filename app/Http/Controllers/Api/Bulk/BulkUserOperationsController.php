<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\BulkInviteUsersRequest;
use App\Models\Organization;
use App\Models\User;
use App\Services\BulkOperationService;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class BulkUserOperationsController extends BaseApiController
{
    protected BulkOperationService $bulkOperationService;

    protected OAuthService $oAuthService;

    public function __construct(BulkOperationService $bulkOperationService, OAuthService $oAuthService)
    {
        $this->bulkOperationService = $bulkOperationService;
        $this->oAuthService = $oAuthService;
        $this->middleware('auth:api');
    }

    /**
     * Bulk invite users to an organization
     */
    public function bulkInviteUsers(BulkInviteUsersRequest $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.create');

        $organization = Organization::findOrFail($organizationId);

        try {
            $result = $this->bulkOperationService->bulkInviteUsers(
                $request->validated()['invitations'],
                $organization,
                'user' // default role
            );

            // The service returns the result directly, not wrapped in success/data structure
            $successful = $result['successful'] ?? [];
            $failed = $result['failed'] ?? [];
            $alreadyExists = $result['already_exists'] ?? [];

            $totalProcessed = count($request->validated()['invitations']);
            $successfulCount = count($successful);
            $failedCount = count($failed);
            $existsCount = count($alreadyExists);

            $message = sprintf(
                'Bulk invitation completed: %d successful, %d failed, %d already exist',
                $successfulCount,
                $failedCount,
                $existsCount
            );

            return $this->successResponse([
                'successful' => $successful,
                'failed' => $failed,
                'already_exists' => $alreadyExists,
                'summary' => [
                    'total_processed' => $totalProcessed,
                    'successful' => $successfulCount,
                    'failed' => $failedCount,
                    'already_exists' => $existsCount,
                    'success_rate' => $totalProcessed > 0 ? round(($successfulCount / $totalProcessed) * 100, 2) : 0,
                ],
            ], $message);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk invitations: '.$e->getMessage());
        }
    }

    /**
     * Bulk assign roles to users
     */
    public function bulkAssignRoles(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('roles.assign');

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|exists:users,id',
            'custom_roles' => 'sometimes|array|min:1',
            'custom_roles.*' => 'exists:custom_roles,id',
            'role' => 'sometimes|string',
            'action' => 'sometimes|string|in:assign,revoke,remove',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $userIds = $request->input('user_ids');
        $customRoleIds = $request->input('custom_roles', []);
        $action = $request->input('action', 'assign');

        // Validate that all users belong to the organization
        $users = User::whereIn('id', $userIds)->get();
        $invalidUsers = $users->filter(function ($user) use ($organization) {
            return $user->organization_id !== $organization->id;
        });

        if ($invalidUsers->isNotEmpty()) {
            return response()->json([
                'message' => 'Some users do not belong to this organization.',
                'invalid_users' => $invalidUsers->pluck('id')->toArray(),
            ], 422);
        }

        try {
            $result = $this->bulkOperationService->bulkAssignOrRevokeRoles(
                $userIds,
                [], // no standard roles
                $customRoleIds, // custom role IDs
                $action,
                $organization,
                auth()->user() ?? \App\Models\User::first()
            );

            // The service returns the result directly, not wrapped in success/data structure
            $successful = $result['successful'] ?? [];
            $failed = $result['failed'] ?? [];

            $totalAssignments = count($request->input('user_ids'));
            $successfulCount = count($successful);
            $failedCount = count($failed);

            $actionText = $action === 'revoke' ? 'revoke' : 'assign';
            $message = sprintf(
                'Bulk role %s completed: %d successful, %d failed',
                $actionText,
                $successfulCount,
                $failedCount
            );

            return $this->successResponse([
                'successful' => $successful,
                'failed' => $failed,
                'summary' => [
                    'total_assignments' => $totalAssignments,
                    'successful' => $successfulCount,
                    'failed' => $failedCount,
                    'success_rate' => $totalAssignments > 0 ? round(($successfulCount / $totalAssignments) * 100, 2) : 0,
                ],
            ], $message);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk role assignments: '.$e->getMessage());
        }
    }
}
