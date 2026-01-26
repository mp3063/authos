<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\ListRequest;
use App\Http\Requests\User\StoreUserRequest;
use App\Http\Requests\User\UpdateUserRequest;
use App\Models\Organization;
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
            return $this->validationErrorResponse($validator->errors());
        }

        $params = $request->getPaginationParams();

        $query = User::query()->with(['roles', 'organization']);

        // Enforce organization-based data isolation for non-super-admin users
        $currentUser = auth()->user();
        if (! $currentUser->hasRole('Super Admin') && ! $currentUser->hasRole('super-admin')) {
            $query->where('organization_id', $currentUser->organization_id);
        }

        // Apply filters
        if ($params['search']) {
            $search = $params['search'];
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                    ->orWhere('email', 'LIKE', "%{$search}%");
            });
        }

        if ($request->has('organization_id')) {
            // Only allow filtering by organization_id if user is super admin or it's their own organization
            if ($currentUser->hasRole('Super Admin') || $currentUser->hasRole('super-admin') ||
                $request->organization_id == $currentUser->organization_id) {
                $query->where('organization_id', $request->organization_id);
            }
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

        $organization = Organization::findOrFail($request->organization_id);
        $user = $this->userManagementService->createUser($userData, $organization);

        $response = $this->userManagementService->formatUserResponse($user);

        return $this->successResponse($response, 'User created successfully', 201);
    }

    /**
     * Display the specified user
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $query = User::with(['roles.permissions', 'organization', 'applications', 'ssoSessions']);

        // Enforce organization-based data isolation for non-super-admin users
        $currentUser = auth()->user();
        if (! $currentUser->hasRole('Super Admin') && ! $currentUser->hasRole('super-admin')) {
            $query->where('organization_id', $currentUser->organization_id);
        }

        $user = $query->findOrFail($id);

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

        return $this->successResponse($response, 'User updated successfully');
    }

    /**
     * Remove the specified user
     */
    public function destroy(string $id): JsonResponse
    {
        // Find user first (returns 404 if not found)
        $user = User::find($id);

        if (! $user) {
            return $this->notFoundResponse('User not found');
        }

        // Check authorization after finding user to return 403 instead of 404
        $this->authorize('users.delete');

        // Prevent self-deletion
        if ($user->id === auth()->id()) {
            return $this->errorResponse('Cannot delete your own account.', 403);
        }

        $this->userManagementService->deleteUser($user);

        return response()->json([], 204);
    }

    /**
     * Get user's applications
     */
    public function applications(Request $request, string $id): JsonResponse
    {
        $this->authorize('users.read');

        // Enforce authorization BEFORE findOrFail to return 403 instead of 404
        $currentUser = auth()->user();
        $user = User::find($id);

        if (! $user) {
            return $this->notFoundResponse('User not found');
        }

        // Users can only view their own applications unless they're admins
        if ($user->id !== $currentUser->id && ! $currentUser->hasRole(['Super Admin', 'Organization Admin'])) {
            return $this->errorResponse('Unauthorized to view other users\' applications', 403);
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
        $this->authorize('users.update');

        // Handle bulk operations
        if ($request->boolean('bulk') && $request->has('user_ids')) {
            return $this->bulkGrantApplicationAccess($request);
        }

        $validator = Validator::make($request->all(), [
            'application_id' => 'required|integer|exists:applications,id',
            'permissions' => 'required|array',
            'permissions.*' => 'string',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $user = User::findOrFail($id);
        $currentUser = auth()->user();

        // Verify application belongs to same organization
        $application = \App\Models\Application::findOrFail($request->application_id);
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
        $validator = Validator::make($request->all(), [
            'application_id' => 'required|integer|exists:applications,id',
            'user_ids' => 'required|array',
            'user_ids.*' => 'integer|exists:users,id',
            'permissions' => 'required|array',
            'permissions.*' => 'string',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $currentUser = auth()->user();
        $application = \App\Models\Application::findOrFail($request->application_id);

        foreach ($request->user_ids as $userId) {
            $user = User::findOrFail($userId);

            // Verify user belongs to same organization as application
            if ($user->organization_id !== $application->organization_id) {
                continue;
            }

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
        $this->authorize('users.update');

        // Handle bulk operations
        if ($request->boolean('bulk') && $request->has('user_ids')) {
            return $this->bulkRevokeApplicationAccess($request, $applicationId);
        }

        $user = User::findOrFail($id);
        $currentUser = auth()->user();

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
        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array',
            'user_ids.*' => 'integer|exists:users,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $currentUser = auth()->user();

        foreach ($request->user_ids as $userId) {
            $user = User::findOrFail($userId);
            $this->userManagementService->revokeApplicationAccess(
                $user,
                (int) $applicationId,
                $currentUser->id
            );
        }

        return $this->successResponse([], 'Application access revoked from users successfully', 200);
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
            return $this->errorResponse('User already has this role.', 409);
        }

        return $this->successResponse([], 'Role assigned successfully', 201);
    }

    /**
     * Update user roles (sync/replace)
     */
    public function updateRoles(Request $request, string $id): JsonResponse
    {
        $this->authorize('roles.assign');

        $validator = Validator::make($request->all(), [
            'roles' => 'required|array',
            'roles.*' => 'required|string|exists:roles,name',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $user = User::findOrFail($id);

        // Sync roles (replace all current roles with new ones)
        $user->syncRoles($request->input('roles'));

        return $this->successResponse([], 'User roles updated successfully');
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
            return $this->errorResponse('User does not have this role.', 404);
        }

        return $this->successResponse([], 'Role removed successfully');
    }

    /**
     * Get user's active sessions
     */
    public function sessions(Request $request, string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        // Check authorization - users can view their own sessions, admins can view any
        $currentUser = auth()->user();
        if ($user->id !== $currentUser->id && ! $currentUser->hasRole(['Super Admin', 'Organization Admin'])) {
            return $this->errorResponse('Forbidden', 403);
        }

        // Get paginated sessions
        $perPage = $request->input('per_page', 15);
        $page = $request->input('page', 1);

        $query = $user->tokens()->where('revoked', false)->orderBy('created_at', 'desc');

        // Check if pagination is requested
        if ($request->has('per_page') || $request->has('page')) {
            $tokens = $query->paginate($perPage, ['*'], 'page', $page);
            $formattedSessions = $this->userManagementService->formatUserSessionsResponse($tokens->getCollection());

            return response()->json([
                'success' => true,
                'data' => $formattedSessions,
                'meta' => [
                    'current_page' => $tokens->currentPage(),
                    'per_page' => $tokens->perPage(),
                    'total' => $tokens->total(),
                    'last_page' => $tokens->lastPage(),
                ],
            ]);
        }

        $sessions = $query->get();
        $formattedSessions = $this->userManagementService->formatUserSessionsResponse($sessions);

        return response()->json([
            'success' => true,
            'data' => $formattedSessions,
        ]);
    }

    /**
     * Show specific session details
     */
    public function showSession(string $id, string $sessionId): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        // Check authorization - users can view their own sessions, admins can view any
        $currentUser = auth()->user();
        if ($user->id !== $currentUser->id && ! $currentUser->hasRole(['Super Admin', 'Organization Admin'])) {
            return $this->errorResponse('Forbidden', 403);
        }

        // Find the specific token
        $token = $user->tokens()->where('id', $sessionId)->first();

        if (! $token) {
            return $this->notFoundResponse('Session not found');
        }

        // Format the token data
        $scopes = $token->scopes;
        if (is_string($scopes)) {
            $scopes = json_decode($scopes, true) ?? [];
        }

        $sessionData = [
            'id' => $token->id,
            'name' => $token->name,
            'scopes' => $scopes ?? [],
            'created_at' => $token->created_at?->toISOString(),
            'expires_at' => $token->expires_at?->toISOString(),
            'last_used_at' => $token->updated_at?->toISOString(),
            'revoked' => (bool) $token->revoked,
        ];

        return $this->successResponse($sessionData);
    }

    /**
     * Revoke all user sessions
     */
    public function revokeSessions(string $id): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $revokedCount = $this->userManagementService->revokeAllUserSessions($user);

        return $this->successResponse([], 'All other sessions revoked successfully');
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
            return $this->errorResponse('Session not found.', 404);
        }

        return $this->successResponse([], 'Session revoked successfully');
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
            return $this->errorResponse('Some users not found or not accessible.', 403);
        }
    }
}
