<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\Organization;
use App\Services\BulkOperationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class BulkAccessController extends BaseApiController
{
    protected BulkOperationService $bulkOperationService;

    public function __construct(BulkOperationService $bulkOperationService)
    {
        $this->bulkOperationService = $bulkOperationService;
        $this->middleware('auth:api');
    }

    /**
     * Bulk revoke user access to applications
     */
    public function bulkRevokeAccess(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('applications.manage');

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'revocations' => 'required|array|min:1|max:100',
            'revocations.*.user_id' => 'required|exists:users,id',
            'revocations.*.application_ids' => 'sometimes|array',
            'revocations.*.application_ids.*' => 'exists:applications,id',
            'revocations.*.revoke_all_applications' => 'sometimes|boolean',
            'revocations.*.revoke_sessions' => 'sometimes|boolean',
            'revocations.*.reason' => 'sometimes|string|max:500',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            // Extract user IDs and application ID from revocations
            $userIds = collect($request->input('revocations'))->pluck('user_id')->toArray();
            $applicationId = $request->input('revocations')[0]['application_ids'][0] ?? null;

            if (! $applicationId) {
                return $this->errorResponse('Application ID is required for access revocation', 400);
            }

            $result = $this->bulkOperationService->bulkRevokeAccess(
                $userIds,
                $applicationId,
                $organization
            );

            if ($result['success']) {
                return $this->successResponse([
                    'processed' => $result['data']['processed'],
                    'failed' => $result['data']['failed'],
                    'summary' => [
                        'total_revocations' => count($request->input('revocations')),
                        'successful' => count($result['data']['processed']),
                        'failed' => count($result['data']['failed']),
                        'applications_revoked' => $result['data']['applications_revoked'] ?? 0,
                        'sessions_revoked' => $result['data']['sessions_revoked'] ?? 0,
                        'success_rate' => count($result['data']['processed']) / count($request->input('revocations')) * 100,
                    ],
                ], $result['message']);
            }

            return $this->errorResponse($result['message'], 400);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk access revocations: '.$e->getMessage());
        }
    }
}
