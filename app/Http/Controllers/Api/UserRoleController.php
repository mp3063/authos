<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Models\Role;
use App\Models\User;
use App\Services\UserRoleService;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Exists;

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
            'role_id' => ['required', 'integer', $this->assignableRoleRule($request, $user, 'id')],
        ]);

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
            'roles.*' => ['required', 'string', $this->assignableRoleRule($request, $user, 'name')->where('guard_name', 'api')],
        ]);

        $roles = Role::query()
            ->where('guard_name', 'api')
            ->whereIn('name', $request->input('roles'))
            ->where(fn (Builder $query) => $this->scopeToAssignableRoles($query, $request, $user))
            ->get();

        $user->syncRoles($roles);

        return $this->successResponse([], 'User roles updated successfully');
    }

    /**
     * Remove role from user
     */
    public function removeRole(string $id, string $roleId): JsonResponse
    {
        $this->authorize('roles.assign');

        $user = User::findOrFail($id);
        $removed = $this->userRoleService->removeRole($user, $roleId);

        if (! $removed) {
            return $this->errorResponse('User does not have this role.', 404);
        }

        return $this->successResponse([], 'Role removed successfully');
    }

    private function assignableRoleRule(Request $request, User $user, string $column): Exists
    {
        return Rule::exists('roles', $column)->where(fn (QueryBuilder $query) => $this->scopeToAssignableRoles($query, $request, $user));
    }

    private function scopeToAssignableRoles(Builder|QueryBuilder $query, Request $request, User $user): void
    {
        $query->where(fn ($organizationRoles) => $organizationRoles
            ->whereNotNull('organization_id')
            ->where('organization_id', $user->organization_id));

        if ($request->user()->isSuperAdmin()) {
            $query->orWhereNull('organization_id');
        }
    }
}
