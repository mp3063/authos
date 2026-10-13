<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Models\Organization;
use App\Models\User;
use App\Models\UserApplication;
use App\Services\BulkOperationService;
use App\Services\UserRoleService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Spatie\Permission\Models\Role;

class BulkAccessController extends BaseController
{
    use ApiControllerHelpers;

    protected BulkOperationService $bulkOperationService;

    public function __construct(BulkOperationService $bulkOperationService, protected UserRoleService $roleService)
    {
        $this->bulkOperationService = $bulkOperationService;
        $this->middleware('auth:api');
    }

    /**
     * Bulk revoke user access to applications
     */
    public function bulkRevokeAccess(Request $request, string $organizationId): JsonResponse
    {
        $organization = Organization::findOrFail($organizationId);

        abort_unless($request->user()->can('view', $organization), 404);
        $this->authorize('create', UserApplication::class);

        // If 'reason' is provided but no application specified, revoke all roles instead of app access
        $revokeAllRoles = ! $request->has('application_id') && ! $request->has('application_ids') && $request->has('reason');

        abort_if($revokeAllRoles && ! $request->user()->hasOrganizationPermission('roles.assign'), 403);

        $request->validate([
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer',
            'application_id' => ['sometimes', Rule::exists('applications', 'id')->where('organization_id', $organization->id)],
            'application_ids' => 'sometimes|array|min:1',
            'application_ids.*' => [Rule::exists('applications', 'id')->where('organization_id', $organization->id)],
            'reason' => 'sometimes|string|max:500',
        ]);

        $userIds = User::whereIn('id', $request->input('user_ids'))
            ->where('organization_id', $organization->id)
            ->pluck('id')
            ->all();
        $applicationId = $request->input('application_id') ?: ($request->input('application_ids')[0] ?? null);

        try {
            if ($revokeAllRoles) {
                $caller = $request->user();
                $revoked = [];
                $failed = [];

                foreach (User::whereIn('id', $userIds)->get() as $user) {
                    $denial = $this->revokeOrganizationRoles($caller, $user, $organization);

                    if ($denial === null) {
                        $revoked[] = ['user_id' => $user->id, 'name' => $user->name];
                    } else {
                        $failed[] = ['user_id' => $user->id, 'error' => $denial];
                    }
                }

                $total = count($request->input('user_ids'));

                return $this->successResponse([
                    'revoked_count' => count($revoked),
                    'successful' => $revoked,
                    'failed' => $failed,
                    'summary' => [
                        'total_revocations' => $total,
                        'successful' => count($revoked),
                        'failed' => $total - count($revoked),
                        'success_rate' => $total > 0 ? round((count($revoked) / $total) * 100, 2) : 0,
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

    private function revokeOrganizationRoles(User $caller, User $target, Organization $organization): ?string
    {
        if ($caller->is($target)) {
            return 'You cannot change your own roles.';
        }

        if (! $caller->can('update', $target)) {
            return 'You are not allowed to change this user\'s roles.';
        }

        $organizationRoleIds = Role::query()->where('organization_id', $organization->id)->pluck('id');

        try {
            $this->roleService->syncRolesAs($caller, $target, $this->roleService->assignedRoleIds($target)->diff($organizationRoleIds)->values());
        } catch (ValidationException $e) {
            return $e->validator->errors()->first();
        }

        return null;
    }
}
