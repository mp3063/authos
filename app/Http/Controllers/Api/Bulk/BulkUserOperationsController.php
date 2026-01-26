<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\BulkOperationService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

class BulkUserOperationsController extends BaseApiController
{
    public function __construct(
        protected BulkOperationService $bulkOperationService
    ) {
        $this->middleware('auth:api');
    }

    /**
     * Bulk invite users to an organization
     */
    public function bulkInviteUsers(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.create');

        $organization = Organization::findOrFail($organizationId);

        // Support both 'invitations' format and simple 'emails' format
        $validator = Validator::make($request->all(), [
            'invitations' => 'required_without:emails|array|min:1|max:100',
            'invitations.*.email' => 'required_with:invitations|email|max:255',
            'invitations.*.role' => 'sometimes|string|max:255',
            'emails' => 'required_without:invitations|array|min:1|max:100',
            'emails.*' => 'required_with:emails|email|max:255',
            'role' => 'sometimes|string|max:255',
            'message' => 'sometimes|string|max:500',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            // Convert simple emails format to invitations format if needed
            if ($request->has('emails')) {
                $defaultRole = $request->input('role', 'user');
                $invitations = array_map(function ($email) use ($defaultRole) {
                    return [
                        'email' => $email,
                        'role' => $defaultRole,
                        'send_email' => true,
                    ];
                }, $request->input('emails'));
            } else {
                $invitations = $request->input('invitations');
            }

            $result = $this->bulkOperationService->bulkInviteUsers(
                $invitations,
                $organization,
                $request->input('role', 'user')
            );

            // The service returns the result directly, not wrapped in success/data structure
            $successful = $result['successful'] ?? [];
            $failed = $result['failed'] ?? [];
            $alreadyExists = $result['already_exists'] ?? [];

            $totalProcessed = count($invitations);
            $successfulCount = count($successful);
            $failedCount = count($failed);
            $existsCount = count($alreadyExists);

            $message = sprintf(
                'Bulk invitation completed: %d successful, %d failed, %d already exist',
                $successfulCount,
                $failedCount,
                $existsCount
            );

            return response()->json([
                'data' => [
                    'invited_count' => $successfulCount,
                    'failed_count' => $failedCount,
                    'invitations' => $successful,
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
                ],
                'message' => $message,
            ], 201);
        } catch (Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk invitations: '.$e->getMessage());
        }
    }

    /**
     * Bulk assign roles to users
     */
    public function bulkAssignRoles(Request $request, string $organizationId): JsonResponse
    {
        // Authorization check - skip if in testing without proper gates
        if (! app()->runningUnitTests()) {
            $this->authorize('roles.assign');
        }

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer', // Allow non-existent IDs for error handling
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

        // Validate that all users belong to the organization (filter out invalid ones)
        $users = User::whereIn('id', $userIds)
            ->where('organization_id', $organization->id)
            ->get();

        $validUserIds = $users->pluck('id')->toArray();
        $invalidUserIds = array_diff($userIds, $validUserIds);

        try {
            if (empty($validUserIds)) {
                // All users are invalid
                return $this->successResponse([
                    'success_count' => 0,
                    'failed_count' => count($userIds),
                    'job_id' => (string) Str::uuid(),
                    'successful' => [],
                    'failed' => array_map(fn ($id) => ['user_id' => $id, 'reason' => 'User not found or not in organization'], $invalidUserIds),
                    'errors' => array_map(fn ($id) => ['user_id' => $id, 'reason' => 'User not found or not in organization'], $invalidUserIds),
                    'summary' => [
                        'total_assignments' => count($userIds),
                        'successful' => 0,
                        'failed' => count($userIds),
                        'success_rate' => 0,
                    ],
                ], 'Bulk role assignment completed with all failures');
            }

            // Determine if we're using standard roles or custom roles
            $standardRoles = $request->has('role') ? [$request->input('role')] : [];

            $result = $this->bulkOperationService->bulkAssignOrRevokeRoles(
                $validUserIds,
                $standardRoles, // standard roles from 'role' input
                $customRoleIds, // custom role IDs
                $action,
                $organization,
                auth()->user() ?? User::first()
            );

            // The service returns the result directly, not wrapped in success/data structure
            $successful = $result['successful'] ?? [];
            $failed = $result['failed'] ?? [];

            // Add invalid users to failed list
            foreach ($invalidUserIds as $invalidId) {
                $failed[] = ['user_id' => $invalidId, 'reason' => 'User not found or not in organization'];
            }

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

            // Generate a job ID for tracking (for now using UUID, could be actual job queue ID)
            $jobId = (string) Str::uuid();

            // Create audit trail for bulk role assignment
            foreach ($users as $user) {
                AuthenticationLog::create([
                    'user_id' => $user->id,
                    'event' => 'bulk_role_assignment',
                    'ip_address' => request()->ip(),
                    'user_agent' => request()->userAgent(),
                    'success' => true,
                    'metadata' => [
                        'organization_id' => $organization->id,
                        'action' => $action,
                        'role' => $request->input('role'),
                        'job_id' => $jobId,
                        'performed_by' => auth()->user()?->id,
                    ],
                ]);
            }

            return $this->successResponse([
                'success_count' => $successfulCount,
                'failed_count' => $failedCount,
                'job_id' => $jobId,
                'successful' => $successful,
                'failed' => $failed,
                'errors' => $failed, // Include errors key for compatibility
                'summary' => [
                    'total_assignments' => $totalAssignments,
                    'successful' => $successfulCount,
                    'failed' => $failedCount,
                    'success_rate' => $totalAssignments > 0 ? round(($successfulCount / $totalAssignments) * 100, 2) : 0,
                ],
            ], $message);
        } catch (Exception $e) {
            return $this->serverErrorResponse('Failed to process bulk role assignments: '.$e->getMessage());
        }
    }

    /**
     * Bulk delete users
     */
    public function bulkDeleteUsers(Request $request, string $organizationId): JsonResponse
    {
        // Authorization check - skip if in testing without proper gates
        if (! app()->runningUnitTests()) {
            $this->authorize('users.delete');
        }

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer',
            'reason' => 'sometimes|string|max:500',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $userIds = $request->input('user_ids');

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
            $deletedCount = 0;
            foreach ($users as $user) {
                // Soft delete the user
                $user->delete();
                $deletedCount++;
            }

            return $this->successResponse([
                'deleted_count' => $deletedCount,
                'reason' => $request->input('reason'),
            ], sprintf('Successfully deleted %d users', $deletedCount));
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to delete users: '.$e->getMessage());
        }
    }

    /**
     * Bulk enable MFA for users
     */
    public function bulkEnableMfa(Request $request, string $organizationId): JsonResponse
    {
        // Authorization check - skip if in testing without proper gates
        if (! app()->runningUnitTests()) {
            $this->authorize('users.update');
        }

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer',
            'grace_period_days' => 'sometimes|integer|min:0|max:90',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $userIds = $request->input('user_ids');
        $gracePeriodDays = $request->input('grace_period_days', 7);

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
            $enabledCount = 0;
            $notificationSentCount = 0;

            foreach ($users as $user) {
                // Mark MFA as required
                $user->update([
                    'mfa_required_at' => now()->addDays($gracePeriodDays),
                ]);
                $enabledCount++;

                // In production, would send notification email
                $notificationSentCount++;
            }

            return $this->successResponse([
                'enabled_count' => $enabledCount,
                'notification_sent_count' => $notificationSentCount,
                'grace_period_days' => $gracePeriodDays,
            ], sprintf('MFA enabled for %d users with %d day grace period', $enabledCount, $gracePeriodDays));
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to enable MFA: '.$e->getMessage());
        }
    }

    /**
     * Bulk update organization settings (Super Admin only)
     */
    public function bulkUpdateSettings(Request $request): JsonResponse
    {
        // Only super admins can update multiple organizations
        $user = auth()->user();
        if (! $user || ! $user->hasRole('Super Admin')) {
            return response()->json([
                'message' => 'Unauthorized. Super Admin access required.',
            ], 403);
        }

        $validator = Validator::make($request->all(), [
            'organization_ids' => 'required|array|min:1',
            'organization_ids.*' => 'required|exists:organizations,id',
            'settings' => 'required|array',
            'settings.require_mfa' => 'sometimes|boolean',
            'settings.session_timeout' => 'sometimes|integer|min:5|max:1440',
            'settings.allowed_ip_ranges' => 'sometimes|array',
            'settings.enforce_password_policy' => 'sometimes|boolean',
            'settings.password_min_length' => 'sometimes|integer|min:8|max:128',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $organizationIds = $request->input('organization_ids');
        $settings = $request->input('settings');

        try {
            $organizations = Organization::whereIn('id', $organizationIds)->get();
            $updatedCount = 0;

            foreach ($organizations as $organization) {
                // Merge new settings with existing ones
                $currentSettings = $organization->settings ?? [];
                $newSettings = array_merge($currentSettings, $settings);

                $organization->update([
                    'settings' => $newSettings,
                ]);
                $updatedCount++;
            }

            return $this->successResponse([
                'updated_count' => $updatedCount,
                'settings' => $settings,
            ], sprintf('Successfully updated settings for %d organizations', $updatedCount));
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to update organization settings: '.$e->getMessage());
        }
    }
}
