<?php

namespace App\Http\Controllers\Api;

use App\Enums\UserRole;
use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Requests\ListRequest;
use App\Http\Requests\User\StoreUserRequest;
use App\Http\Requests\User\UpdateUserRequest;
use App\Models\Organization;
use App\Models\User;
use App\Services\UserManagementService;
use App\Services\UserRoleService;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use InvalidArgumentException;

class UserController extends BaseController
{
    use ApiControllerHelpers;

    protected UserManagementService $userManagementService;

    public function __construct(UserManagementService $userManagementService, protected UserRoleService $userRoleService)
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
        $request->validate([
            'organization_id' => 'sometimes|integer|exists:organizations,id',
            'role' => 'sometimes|string|exists:roles,name',
            'mfa_enabled' => 'sometimes|boolean',
        ]);

        $params = $request->getPaginationParams();

        $query = User::query()->with(['roles', 'organization']);

        // Enforce organization-based data isolation for non-super-admin users
        $currentUser = auth()->user();
        if (! $this->hasSuperAdminRole($currentUser)) {
            $query->where('organization_id', $currentUser->organization_id);
        }

        $this->applySearchFilter($query, $params['search']);
        $this->applyOrganizationFilter($query, $request, $currentUser);
        $this->applyRoleAndMfaFilters($query, $request);
        $this->applyActiveFilter($query, $request);

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

    private function hasSuperAdminRole(User $user): bool
    {
        return $user->hasRole(UserRole::SuperAdmin->label()) || $user->hasRole(UserRole::SuperAdmin->value);
    }

    private function applySearchFilter(Builder $query, mixed $search): void
    {
        if (! $search) {
            return;
        }

        $query->where(function ($searchQuery) use ($search) {
            $searchQuery->where('name', 'LIKE', "%{$search}%")
                ->orWhere('email', 'LIKE', "%{$search}%");
        });
    }

    private function applyOrganizationFilter(Builder $query, ListRequest $request, User $currentUser): void
    {
        // Only allow filtering by organization_id if user is super admin or it's their own organization
        if ($request->has('organization_id') &&
            ($this->hasSuperAdminRole($currentUser) || $request->organization_id == $currentUser->organization_id)) {
            $query->where('organization_id', $request->organization_id);
        }
    }

    private function applyRoleAndMfaFilters(Builder $query, ListRequest $request): void
    {
        if ($request->has('role')) {
            $query->whereHas('roles', function ($roleQuery) use ($request) {
                $roleQuery->where('name', $request->role);
            });
        }

        if ($request->has('mfa_enabled')) {
            if ($request->mfa_enabled) {
                $query->whereNotNull('mfa_methods');
            } else {
                $query->whereNull('mfa_methods');
            }
        }
    }

    private function applyActiveFilter(Builder $query, ListRequest $request): void
    {
        if (! $request->has('filter.is_active')) {
            return;
        }

        $isActiveFilter = $request->input('filter.is_active');
        if ($isActiveFilter === 'true' || $isActiveFilter === true || $isActiveFilter === '1') {
            $query->where('is_active', true);
        } elseif ($isActiveFilter === 'false' || $isActiveFilter === false || $isActiveFilter === '0') {
            $query->where('is_active', false);
        }
    }

    /**
     * Store a newly created user
     */
    public function store(StoreUserRequest $request): JsonResponse
    {
        $organization = Organization::findOrFail($request->organization_id);
        $roles = $this->userRoleService->assignableApiRolesByName($request->user(), $organization->id, $request->getRoles());

        if ($request->has('roles') && $denial = $this->userRoleService->roleChangeDenial($request->user(), null, $roles)) {
            return $this->forbiddenResponse($denial);
        }

        $userData = [
            'name' => $request->name,
            'email' => $request->email,
            'password' => $request->password,
            'profile' => $request->input('profile', []),
            'roles' => $roles,
        ];

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
        if (! $this->hasSuperAdminRole($currentUser)) {
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

        if ($this->userRoleService->exceedsPermissionsOf($request->user(), $this->userRoleService->effectivePermissionNames($user))) {
            return $this->forbiddenResponse('You cannot update a user with permissions you do not have.');
        }

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
     * Handle bulk operations on users
     */
    public function bulk(Request $request): JsonResponse
    {
        $this->authorize('users.update');

        $request->validate([
            'user_ids' => 'required|array|min:1',
            'user_ids.*' => 'integer|exists:users,id',
            'action' => 'required|string|in:activate,deactivate,delete',
        ]);

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
        } catch (InvalidArgumentException $e) {
            return $this->errorResponse('Some users not found or not accessible.', 403);
        }
    }
}
