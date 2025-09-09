<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\ListRequest;
use App\Http\Requests\User\StoreUserRequest;
use App\Http\Requests\User\UpdateUserRequest;
use App\Models\User;
use App\Services\UserManagementService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class UserController extends BaseApiController
{
    protected UserManagementService $userManagementService;

    public function __construct(UserManagementService $userManagementService)
    {
        $this->userManagementService = $userManagementService;
        $this->middleware('auth:api');
    }

    /**
     * Display a paginated listing of users
     */
    public function index(ListRequest $request): JsonResponse
    {
        $this->authorize('users.read');

        // Additional validation for user-specific filters
        $validator = Validator::make($request->all(), [
            'organization_id' => 'sometimes|integer|exists:organizations,id',
            'role' => 'sometimes|string|exists:roles,name',
            'mfa_enabled' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $params = $request->getPaginationParams();

        $query = User::query()->with(['roles', 'organization']);

        // Apply filters
        if ($params['search']) {
            $search = $params['search'];
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                    ->orWhere('email', 'LIKE', "%{$search}%");
            });
        }

        if ($request->has('organization_id')) {
            $query->where('organization_id', $request->organization_id);
        }

        if ($request->has('role')) {
            $query->whereHas('roles', function ($q) use ($request) {
                $q->where('name', $request->role);
            });
        }

        if ($request->has('mfa_enabled')) {
            if ($request->mfa_enabled) {
                $query->whereNotNull('mfa_methods');
            } else {
                $query->whereNull('mfa_methods');
            }
        }

        // Handle is_active filter
        if ($request->has('filter.is_active')) {
            $isActiveFilter = $request->input('filter.is_active');
            if ($isActiveFilter === 'true' || $isActiveFilter === true || $isActiveFilter === '1') {
                $query->where('is_active', true);
            } elseif ($isActiveFilter === 'false' || $isActiveFilter === false || $isActiveFilter === '0') {
                $query->where('is_active', false);
            }
        }

        // Apply sorting
        $sort = $params['sort'] ?? 'created_at';
        $order = $params['order'];
        if (in_array($sort, ['name', 'email', 'created_at', 'updated_at'])) {
            $query->orderBy($sort, $order);
        } else {
            $query->orderBy('created_at', $order);
        }

        // Paginate
        $users = $query->paginate($params['per_page']);

        // Transform the paginated data using the service
        $users->getCollection()->transform(function ($user) {
            return $this->userManagementService->formatUserResponse($user);
        });

        return $this->paginatedResponse($users);
    }

    /**
     * Store a newly created user
     */
    public function store(StoreUserRequest $request): JsonResponse
    {
        $userData = [
            'name' => $request->name,
            'email' => $request->email,
            'password' => $request->password,
            'profile' => $request->input('profile', []),
            'roles' => $request->getRoles(),
        ];

        $organization = \App\Models\Organization::findOrFail($request->organization_id);
        $user = $this->userManagementService->createUser($userData, $organization);

        $response = $this->userManagementService->formatUserResponse($user);
        $response['message'] = 'User created successfully';

        return $this->successResponse($response, 201);
    }

    /**
     * Display the specified user
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::with(['roles.permissions', 'organization', 'applications', 'ssoSessions'])
            ->withCount(['applications', 'ssoSessions'])
            ->findOrFail($id);

        return $this->successResponse($this->userManagementService->formatUserResponse($user, true));
    }

    /**
     * Update the specified user
     */
    public function update(UpdateUserRequest $request, string $id): JsonResponse
    {
        $user = User::findOrFail($id);

        $updateData = $request->only(['name', 'email', 'organization_id', 'profile', 'is_active']);

        if ($request->has('password')) {
            $updateData['password'] = $request->password;
        }

        $updatedUser = $this->userManagementService->updateUser($user, $updateData);

        $response = $this->userManagementService->formatUserResponse($updatedUser);
        $response['message'] = 'User updated successfully';

        return $this->successResponse($response);
    }

    /**
     * Remove the specified user
     */
    public function destroy(string $id): JsonResponse
    {
        $this->authorize('users.delete');

        $user = User::findOrFail($id);

        // Prevent self-deletion
        if ($user->id === auth()->id()) {
            return $this->errorResponse('Cannot delete your own account.', 'authorization_failed', 403);
        }

        $this->userManagementService->deleteUser($user);

        return response()->json([], 204);
    }

    /**
     * Get user's applications
     */
    public function applications(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);
        $applications = $user->applications()
            ->withPivot(['last_login_at', 'login_count', 'permissions'])
            ->get();

        return $this->successResponse([
            'data' => $this->userManagementService->formatUserApplicationsResponse($applications),
        ]);
    }

    /**
     * Grant user access to application
     */
    public function grantApplicationAccess(Request $request, string $id): JsonResponse
    {
        $this->authorize('users.update');

        $validator = Validator::make($request->all(), [
            'application_id' => 'required|integer|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $user = User::findOrFail($id);
        $granted = $this->userManagementService->grantApplicationAccess($user, $request->application_id);

        if (! $granted) {
            return $this->errorResponse('User already has access to this application.', 'resource_conflict', 409);
        }

        return $this->successResponse([
            'message' => 'Application access granted successfully',
        ], 201);
    }

    /**
     * Revoke user access to application
     */
    public function revokeApplicationAccess(string $id, string $applicationId): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $revoked = $this->userManagementService->revokeApplicationAccess($user, (int) $applicationId);

        if (! $revoked) {
            return $this->errorResponse('User does not have access to this application.', 'resource_not_found', 404);
        }

        return $this->successResponse([
            'message' => 'Application access revoked successfully',
        ]);
    }

    /**
     * Get user's roles
     */
    public function roles(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        return $this->successResponse([
            'data' => $this->userManagementService->formatUserRolesResponse($user->roles),
        ]);
    }

    /**
     * Assign role to user
     */
    public function assignRole(Request $request, string $id): JsonResponse
    {
        $this->authorize('roles.assign');

        $validator = Validator::make($request->all(), [
            'role_id' => 'required|integer|exists:roles,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $user = User::findOrFail($id);
        $assigned = $this->userManagementService->assignRole($user, (string) $request->role_id);

        if (! $assigned) {
            return $this->errorResponse('User already has this role.', 'resource_conflict', 409);
        }

        return $this->successResponse([
            'message' => 'Role assigned successfully',
        ], 201);
    }

    /**
     * Remove role from user
     */
    public function removeRole(string $id, string $roleId): JsonResponse
    {
        $this->authorize('roles.assign');

        $user = User::findOrFail($id);
        $removed = $this->userManagementService->removeRole($user, $roleId);

        if (! $removed) {
            return $this->errorResponse('User does not have this role.', 'resource_not_found', 404);
        }

        return $this->successResponse([
            'message' => 'Role removed successfully',
        ]);
    }

    /**
     * Get user's active sessions
     */
    public function sessions(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);
        $sessions = $this->userManagementService->getUserSessions($user);

        return $this->successResponse([
            'data' => $this->userManagementService->formatUserSessionsResponse($sessions),
        ]);
    }

    /**
     * Revoke all user sessions
     */
    public function revokeSessions(string $id): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $revokedCount = $this->userManagementService->revokeAllUserSessions($user);

        return $this->successResponse([
            'message' => 'All user sessions revoked successfully',
            'revoked_count' => $revokedCount,
        ]);
    }

    /**
     * Revoke specific user session
     */
    public function revokeSession(string $id, string $sessionId): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $revoked = $this->userManagementService->revokeUserSession($user, $sessionId);

        if (! $revoked) {
            return $this->errorResponse('Session not found.', 'resource_not_found', 404);
        }

        return $this->successResponse([
            'message' => 'Session revoked successfully',
        ]);
    }

    /**
     * Handle bulk operations on users
     */
    public function bulk(Request $request): JsonResponse
    {
        $this->authorize('users.update');

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1',
            'user_ids.*' => 'integer|exists:users,id',
            'action' => 'required|string|in:activate,deactivate,delete',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            $result = $this->userManagementService->performBulkOperation(
                $request->input('user_ids'),
                $request->input('action'),
                $request->user()
            );

            return $this->successResponse([
                'message' => 'Bulk operation completed successfully',
                'affected_count' => $result['affected_count'],
            ]);
        } catch (\InvalidArgumentException $e) {
            return $this->errorResponse('Some users not found or not accessible.', 'access_denied', 403);
        }
    }
}
