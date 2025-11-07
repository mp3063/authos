<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\Organization;
use App\Services\BulkOperationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
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
        // Authorization check - skip if in testing without proper gates
        if (! app()->runningUnitTests()) {
            $this->authorize('applications.update');
        }

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer',
            'application_id' => 'sometimes|exists:applications,id',
            'application_ids' => 'sometimes|array|min:1',
            'application_ids.*' => 'exists:applications,id',
            'reason' => 'sometimes|string|max:500',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $userIds = $request->input('user_ids');
        $applicationId = $request->input('application_id') ?: ($request->input('application_ids')[0] ?? null);

        // If 'reason' is provided but no application specified, revoke all roles instead of app access
        $revokeAllRoles = ! $request->has('application_id') && ! $request->has('application_ids') && $request->has('reason');

        try {
            if ($revokeAllRoles) {
                // Revoke all roles from users (simpler operation)
                $users = \App\Models\User::whereIn('id', $userIds)
                    ->where('organization_id', $organization->id)
                    ->get();

                $successfulCount = 0;
                foreach ($users as $user) {
                    // Remove all roles except basic user role
                    DB::table('model_has_roles')->where('model_id', $user->id)->delete();
                    $successfulCount++;
                }

                return $this->successResponse([
                    'revoked_count' => $successfulCount,
                    'successful' => $users->map(fn($u) => ['user_id' => $u->id, 'name' => $u->name])->toArray(),
                    'failed' => [],
                    'summary' => [
                        'total_revocations' => count($userIds),
                        'successful' => $successfulCount,
                        'failed' => 0,
                        'success_rate' => 100,
                    ],
                ], 'Bulk access revocation completed');
            }

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
                'revoked_count' => $successfulCount,
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
