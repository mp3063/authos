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
        $this->authorize('applications.update');

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|exists:users,id',
            'application_id' => 'sometimes|exists:applications,id',
            'application_ids' => 'sometimes|array|min:1',
            'application_ids.*' => 'exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        // Check that at least one application field is provided
        if (! $request->has('application_id') && ! $request->has('application_ids')) {
            return $this->validationErrorResponse(['application_id' => ['Either application_id or application_ids is required']]);
        }

        $userIds = $request->input('user_ids');
        $applicationId = $request->input('application_id') ?: ($request->input('application_ids')[0] ?? null);

        try {
            $result = $this->bulkOperationService->bulkRevokeAccess(
                $userIds,
                $applicationId,
                $organization
            );

            // The service returns the result directly, not wrapped in success/data structure
            $successful = $result['successful'] ?? [];
            $failed = $result['failed'] ?? [];

            $totalRevocations = count($request->input('user_ids'));
            $successfulCount = count($successful);
            $failedCount = count($failed);

            $message = sprintf(
                'Bulk access revocation completed: %d successful, %d failed',
                $successfulCount,
                $failedCount
            );

            return $this->successResponse([
                'successful' => $successful,
                'failed' => $failed,
                'summary' => [
                    'total_revocations' => $totalRevocations,
                    'successful' => $successfulCount,
                    'failed' => $failedCount,
                    'success_rate' => $totalRevocations > 0 ? round(($successfulCount / $totalRevocations) * 100, 2) : 0,
                ],
            ], $message);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk access revocations: '.$e->getMessage());
        }
    }
}
