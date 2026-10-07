<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Models\Role;
use App\Models\User;
use App\Services\UserRoleService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class UserRoleController extends BaseController
{
    use ApiControllerHelpers;

    public function __construct(protected UserRoleService $userRoleService)
    {
        $this->middleware('auth:api');
    }

    /**
     * Get user's roles
     */
    public function roles(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        return $this->successResponse([
            'data' => $this->userRoleService->formatUserRolesResponse($user->roles),
        ]);
    }

    /**
     * Assign role to user
     */
    public function assignRole(Request $request, string $id): JsonResponse
    {
        $this->authorize('roles.assign');

        $user = User::findOrFail($id);

        $request->validate([
            'role_id' => ['required', 'integer', $this->userRoleService->assignableRoleRule($request->user(), $user->organization_id, 'id')],
        ]);

        if ($denial = $this->userRoleService->roleChangeDenial($request->user(), $user, Role::whereKey($request->role_id)->get())) {
            return $this->forbiddenResponse($denial);
        }

        $assigned = $this->userRoleService->assignRole($user, (string) $request->role_id);

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

        $user = User::findOrFail($id);

        $request->validate([
            'roles' => 'required|array',
            'roles.*' => ['required', 'string', $this->userRoleService->assignableRoleRule($request->user(), $user->organization_id, 'name')->where('guard_name', 'api')],
        ]);

        $roles = $this->userRoleService->assignableApiRolesByName($request->user(), $user->organization_id, $request->input('roles'));

        if ($denial = $this->userRoleService->roleChangeDenial($request->user(), $user, $roles->merge($user->roles))) {
            return $this->forbiddenResponse($denial);
        }

        $user->syncRoles($roles);

        return $this->successResponse([], 'User roles updated successfully');
    }

    /**
     * Remove role from user
     */
    public function removeRole(Request $request, string $id, string $roleId): JsonResponse
    {
        $this->authorize('roles.assign');

        $user = User::findOrFail($id);

        if ($denial = $this->userRoleService->roleChangeDenial($request->user(), $user, Role::whereKey($roleId)->get())) {
            return $this->forbiddenResponse($denial);
        }

        $removed = $this->userRoleService->removeRole($user, $roleId);

        if (! $removed) {
            return $this->errorResponse('User does not have this role.', 404);
        }

        return $this->successResponse([], 'Role removed successfully');
    }
}
