<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Api\Traits\FindsOrgScopedOrganizations;
use App\Models\AuthenticationLog;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\BulkOperationService;
use App\Services\UserRoleService;
use Exception;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class BulkUserOperationsController extends BaseController
{
    use ApiControllerHelpers;
    use FindsOrgScopedOrganizations;

    public function __construct(
        protected BulkOperationService $bulkOperationService,
        protected UserRoleService $userRoleService
    ) {
        $this->middleware('auth:api');
    }

    /**
     * Bulk invite users to an organization
     */
    public function bulkInviteUsers(Request $request, string $organizationId): JsonResponse
    {
        $organization = $this->findOrganizationWithOrgScope($organizationId);
        $this->authorize('create', Invitation::class);

        // Support both 'invitations' format and simple 'emails' format
        $request->validate([
            'invitations' => 'required_without:emails|array|min:1|max:100',
            'invitations.*.email' => 'required_with:invitations|email|max:255',
            'invitations.*.role' => 'sometimes|string|max:255',
            'invitations.*.custom_role_id' => 'nullable|integer',
            'invitations.*.expires_in_days' => 'sometimes|integer|min:1|max:30',
            'emails' => 'required_without:invitations|array|min:1|max:100',
            'emails.*' => 'required_with:emails|email|max:255',
            'role' => 'sometimes|string|max:255',
            'message' => 'sometimes|string|max:500',
        ]);

        $this->assertInvitedCustomRolesGrantable($request, $organization);

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
                $request->input('role', 'user'),
                $request->user()
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
            report($e);

            return $this->serverErrorResponse('Failed to process bulk invitations');
        }
    }

    /**
     * Bulk assign roles to users
     */
    public function bulkAssignRoles(Request $request, string $organizationId): JsonResponse
    {
        $organization = $this->findOrganizationWithOrgScope($organizationId);
        $this->authorize('roles.assign');

        $request->validate([
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer', // Allow non-existent IDs for error handling
            'custom_roles' => 'sometimes|array|min:1',
            'custom_roles.*' => [Rule::exists('custom_roles', 'id')->where('organization_id', $organization->id)],
            'role' => 'sometimes|string',
            'action' => 'sometimes|string|in:assign,revoke,remove',
        ]);

        $userIds = $request->input('user_ids');
        $customRoleIds = $request->input('custom_roles', []);
        $action = $request->input('action', 'assign');

        // Validate that all users belong to the organization (filter out invalid ones)
        $users = User::whereIn('id', $userIds)
            ->where('organization_id', $organization->id)
            ->get();

        $validUserIds = $users->pluck('id')->toArray();
        $invalidUserIds = array_diff($userIds, $validUserIds);

        if ($denial = $this->roleChangeDenial($request, $organization, $validUserIds, $customRoleIds)) {
            return $this->forbiddenResponse($denial);
        }

        [$users, $protectedUsers] = $users->partition(fn (User $user) => $request->user()->can('update', $user));

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
                $users->modelKeys(),
                $standardRoles, // standard roles from 'role' input
                $customRoleIds, // custom role IDs
                $action,
                $organization,
                $request->user()
            );

            // The service returns the result directly, not wrapped in success/data structure
            $successful = $result['successful'] ?? [];
            $failed = $result['failed'] ?? [];

            foreach ($protectedUsers as $protectedUser) {
                $failed[] = ['user_id' => $protectedUser->id, 'reason' => 'You are not allowed to change this user\'s roles.'];
            }

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
            report($e);

            return $this->serverErrorResponse('Failed to process bulk role assignments');
        }
    }

    /**
     * Bulk delete users
     */
    public function bulkDeleteUsers(Request $request, string $organizationId): JsonResponse
    {
        $organization = $this->findOrganizationWithOrgScope($organizationId);
        $this->authorize('deleteAny', User::class);

        $request->validate([
            'user_ids' => 'required|array|min:1|max:100',
            'user_ids.*' => 'required|integer',
            'reason' => 'sometimes|string|max:500',
        ]);

        $userIds = $request->input('user_ids');

        $users = User::with(['permissions', 'roles.permissions'])
            ->whereIn('id', $userIds)
            ->where('organization_id', $organization->id)
            ->get();

        try {
            $caller = $request->user();
            $deletedCount = 0;
            foreach ($users as $user) {
                if (! $caller->can('delete', $user)) {
                    continue;
                }

                // Soft delete the user
                $user->delete();
                $deletedCount++;
            }

            return $this->successResponse([
                'deleted_count' => $deletedCount,
                'reason' => $request->input('reason'),
            ], sprintf('Successfully deleted %d users', $deletedCount));
        } catch (Exception $e) {
            report($e);

            return $this->serverErrorResponse('Failed to delete users');
        }
    }

    /**
     * Bulk update organization settings (Super Admin only)
     */
    public function bulkUpdateSettings(Request $request): JsonResponse
    {
        // Only super admins can update multiple organizations
        $user = auth()->user();
        if (! $user || ! $user->isSuperAdmin()) {
            return response()->json([
                'message' => 'Unauthorized. Super Admin access required.',
            ], 403);
        }

        $request->validate([
            'organization_ids' => 'required|array|min:1',
            'organization_ids.*' => 'required|exists:organizations,id',
            'settings' => 'required|array',
            'settings.require_mfa' => 'sometimes|boolean',
            'settings.session_timeout' => 'sometimes|integer|min:5|max:1440',
            'settings.allowed_ip_ranges' => 'sometimes|array',
            'settings.enforce_password_policy' => 'sometimes|boolean',
            'settings.password_min_length' => 'sometimes|integer|min:8|max:128',
        ]);

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
        } catch (Exception $e) {
            report($e);

            return $this->serverErrorResponse('Failed to update organization settings');
        }
    }

    /**
     * @throws ValidationException
     */
    private function assertInvitedCustomRolesGrantable(Request $request, Organization $organization): void
    {
        $caller = $request->user();

        if ($caller->isSuperAdmin()) {
            return;
        }

        $errors = [];

        foreach ($request->input('invitations', []) as $index => $invitation) {
            if (! isset($invitation['custom_role_id'])) {
                continue;
            }

            $customRole = CustomRole::where('id', $invitation['custom_role_id'])
                ->where('organization_id', $organization->id)
                ->first();

            if ($customRole && ! $customRole->is_active) {
                $errors["invitations.{$index}.custom_role_id"] = 'The selected custom role is not active.';
            } elseif ($customRole && $this->userRoleService->exceedsPermissionsOf($caller, collect($customRole->permissions ?? []))) {
                $errors["invitations.{$index}.custom_role_id"] = 'You cannot grant a role with permissions you do not have.';
            }
        }

        if ($errors !== []) {
            throw ValidationException::withMessages($errors);
        }
    }

    /**
     * @param  array<int, int>  $userIds
     * @param  array<int, int|string>  $customRoleIds
     */
    private function roleChangeDenial(Request $request, Organization $organization, array $userIds, array $customRoleIds): ?string
    {
        $caller = $request->user();

        if ($caller->isSuperAdmin()) {
            return null;
        }

        if (in_array($caller->id, $userIds, true)) {
            return 'You cannot change your own roles.';
        }

        $standardRoles = $request->has('role')
            ? Role::where('organization_id', $organization->id)
                ->whereRaw('LOWER(name) = LOWER(?)', [(string) $request->input('role')])
                ->get()
            : new EloquentCollection;
        $customRolePermissions = CustomRole::whereIn('id', $customRoleIds)
            ->where('organization_id', $organization->id)
            ->get()
            ->pluck('permissions')
            ->flatten();

        if ($this->userRoleService->roleChangeDenial($caller, null, $standardRoles)
            || $this->userRoleService->exceedsPermissionsOf($caller, $customRolePermissions)) {
            return 'You cannot grant or revoke a role with permissions you do not have.';
        }

        return null;
    }
}
