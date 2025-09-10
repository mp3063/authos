<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\BulkInviteUsersRequest;
use App\Http\Resources\InvitationResource;
use App\Models\Organization;
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

            if ($result['success']) {
                return $this->successResponse([
                    'invited' => $result['data']['invited'],
                    'failed' => $result['data']['failed'],
                    'invitations' => InvitationResource::collection($result['data']['created_invitations']),
                    'summary' => [
                        'total_processed' => count($request->validated()['invitations']),
                        'successful' => count($result['data']['invited']),
                        'failed' => count($result['data']['failed']),
                        'success_rate' => count($result['data']['invited']) / count($request->validated()['invitations']) * 100,
                    ],
                ], $result['message']);
            }

            return $this->errorResponse($result['message'], 400);
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
            'assignments' => 'required|array|min:1|max:100',
            'assignments.*.user_id' => 'required|exists:users,id',
            'assignments.*.role_ids' => 'required|array|min:1',
            'assignments.*.role_ids.*' => 'exists:roles,id',
            'assignments.*.action' => 'sometimes|string|in:assign,remove',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            // Extract user IDs and role ID from assignments
            $userIds = collect($request->input('assignments'))->pluck('user_id')->toArray();
            $roleId = $request->input('assignments')[0]['role_ids'][0] ?? 'user'; // Get first role from first assignment

            $result = $this->bulkOperationService->bulkAssignRoles(
                $userIds,
                $roleId,
                $organization
            );

            if ($result['success']) {
                return $this->successResponse([
                    'processed' => $result['data']['processed'],
                    'failed' => $result['data']['failed'],
                    'summary' => [
                        'total_assignments' => count($request->input('assignments')),
                        'successful' => count($result['data']['processed']),
                        'failed' => count($result['data']['failed']),
                        'success_rate' => count($result['data']['processed']) / count($request->input('assignments')) * 100,
                    ],
                ], $result['message']);
            }

            return $this->errorResponse($result['message'], 400);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk role assignments: '.$e->getMessage());
        }
    }
}
