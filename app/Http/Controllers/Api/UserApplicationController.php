<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Api\Traits\FindsOrgScopedApplications;
use App\Models\User;
use App\Models\UserApplication;
use App\Services\UserManagementService;
use App\Services\UserRoleService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Validation\ValidationException;

class UserApplicationController extends BaseController
{
    use ApiControllerHelpers;
    use FindsOrgScopedApplications;

    public function __construct(protected UserManagementService $userManagementService, protected UserRoleService $userRoleService)
    {
        $this->middleware('auth:api');
    }

    /**
     * Get user's applications
     */
    public function applications(Request $request, string $id): JsonResponse
    {
        $currentUser = auth()->user();
        $user = $this->findUserWithOrgScope($id);

        if ($user->id !== $currentUser->id) {
            $this->authorize('create', UserApplication::class);
        }

        // Build query with pivot data
        $query = $user->applications()
            ->withPivot(['permissions', 'granted_at', 'granted_by', 'last_login_at', 'login_count']);

        // Apply permission filter if provided
        if ($request->has('permission')) {
            $permission = $request->input('permission');
            // Use LIKE for SQLite/PostgreSQL compatibility
            $query->where('user_applications.permissions', 'LIKE', '%"'.$permission.'"%');
        }

        // Handle pagination
        $perPage = $request->input('per_page', 15);
        $page = $request->input('page', 1);

        if ($request->has('per_page') || $request->has('page')) {
            $applications = $query->paginate($perPage, ['*'], 'page', $page);

            // Transform applications to ensure pivot data is properly formatted
            $transformedItems = collect($applications->items())->map(function ($app) {
                $data = $app->toArray();
                // Ensure permissions is an array, not a JSON string
                if (isset($data['pivot']['permissions']) && is_string($data['pivot']['permissions'])) {
                    $data['pivot']['permissions'] = json_decode($data['pivot']['permissions'], true) ?? [];
                }

                return $data;
            })->toArray();

            $response = [
                'success' => true,
                'data' => $transformedItems,
                'meta' => [
                    'current_page' => $applications->currentPage(),
                    'per_page' => $applications->perPage(),
                    'total' => $applications->total(),
                    'last_page' => $applications->lastPage(),
                ],
            ];

            return response()->json($response, 200);
        }

        $applications = $query->get();

        // Transform applications to ensure pivot data is properly formatted
        $transformedApplications = $applications->map(function ($app) {
            $data = $app->toArray();
            // Ensure permissions is an array, not a JSON string
            if (isset($data['pivot']['permissions']) && is_string($data['pivot']['permissions'])) {
                $data['pivot']['permissions'] = json_decode($data['pivot']['permissions'], true) ?? [];
            }

            return $data;
        });

        $response = [
            'success' => true,
            'data' => $transformedApplications,
        ];

        return response()->json($response, 200);
    }

    /**
     * Grant user access to application (single or bulk)
     */
    public function grantApplicationAccess(Request $request, string $id): JsonResponse
    {
        $this->authorize('create', UserApplication::class);

        // Handle bulk operations
        if ($request->boolean('bulk') && $request->has('user_ids')) {
            return $this->bulkGrantApplicationAccess($request);
        }

        $request->validate([
            'application_id' => 'required|integer|exists:applications,id',
            'permissions' => 'required|array',
            'permissions.*' => 'string',
        ]);

        $this->assertPermissionsWithinCallerGrants($request->permissions);

        $user = $this->findUserWithOrgScope($id);
        $currentUser = auth()->user();

        $application = $this->findApplicationWithOrgScope((string) $request->application_id, 'update');
        if ($application->organization_id !== $user->organization_id) {
            return $this->errorResponse('Application does not belong to user\'s organization', 403);
        }

        $granted = $this->userManagementService->grantApplicationAccess(
            $user,
            $request->application_id,
            $request->permissions,
            $currentUser->id
        );

        if (! $granted) {
            return $this->errorResponse('User already has access to this application.', 409);
        }

        return $this->successResponse([], 'Application access granted successfully', 200);
    }

    /**
     * Bulk grant application access
     */
    private function bulkGrantApplicationAccess(Request $request): JsonResponse
    {
        $request->validate([
            'application_id' => 'required|integer|exists:applications,id',
            'user_ids' => 'required|array',
            'user_ids.*' => 'integer|exists:users,id',
            'permissions' => 'required|array',
            'permissions.*' => 'string',
        ]);

        $this->assertPermissionsWithinCallerGrants($request->permissions);

        $currentUser = auth()->user();
        $application = $this->findApplicationWithOrgScope((string) $request->application_id, 'update');

        $users = User::whereIn('id', $request->user_ids)
            ->where('organization_id', $application->organization_id)
            ->get();

        foreach ($users as $user) {
            $this->userManagementService->grantApplicationAccess(
                $user,
                $request->application_id,
                $request->permissions,
                $currentUser->id
            );
        }

        return $this->successResponse([], 'Application access granted to users successfully', 200);
    }

    /**
     * Revoke user access to application (single or bulk)
     */
    public function revokeApplicationAccess(Request $request, string $id, string $applicationId): JsonResponse
    {
        $this->authorize('create', UserApplication::class);

        // Handle bulk operations
        if ($request->boolean('bulk') && $request->has('user_ids')) {
            return $this->bulkRevokeApplicationAccess($request, $applicationId);
        }

        $user = $this->findUserWithOrgScope($id);
        $currentUser = auth()->user();

        $this->findApplicationWithOrgScope($applicationId, 'update');

        $revoked = $this->userManagementService->revokeApplicationAccess(
            $user,
            (int) $applicationId,
            $currentUser->id
        );

        if (! $revoked) {
            return $this->errorResponse('User does not have access to this application.', 404);
        }

        return $this->successResponse([], 'Application access revoked successfully');
    }

    /**
     * Bulk revoke application access
     */
    private function bulkRevokeApplicationAccess(Request $request, string $applicationId): JsonResponse
    {
        $request->validate([
            'user_ids' => 'required|array',
            'user_ids.*' => 'integer|exists:users,id',
        ]);

        $currentUser = auth()->user();
        $this->findApplicationWithOrgScope($applicationId, 'update');

        $users = User::whereIn('id', $request->user_ids)
            ->when(! $currentUser->isSuperAdmin(), fn ($query) => $query
                ->whereNotNull('organization_id')
                ->where('organization_id', $currentUser->organization_id))
            ->get();

        foreach ($users as $user) {
            $this->userManagementService->revokeApplicationAccess(
                $user,
                (int) $applicationId,
                $currentUser->id
            );
        }

        return $this->successResponse([], 'Application access revoked from users successfully', 200);
    }

    /**
     * @param  array<int, string>  $permissions
     */
    private function assertPermissionsWithinCallerGrants(array $permissions): void
    {
        $caller = auth()->user();

        if ($caller->isSuperAdmin()) {
            return;
        }

        if (array_diff($permissions, $this->userRoleService->effectivePermissionNames($caller)->all()) !== []) {
            throw ValidationException::withMessages([
                'permissions' => 'You cannot grant permissions you do not hold.',
            ]);
        }
    }
}
