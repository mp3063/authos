<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;

class CustomRoleController extends Controller
{
    protected OAuthService $oAuthService;

    public function __construct(OAuthService $oAuthService)
    {
        $this->oAuthService = $oAuthService;
        $this->middleware('auth:api');
    }

    /**
     * Display a listing of custom roles for an organization
     */
    public function index(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('roles.read');

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,display_name,created_at,updated_at',
            'order' => 'sometimes|string|in:asc,desc',
            'is_active' => 'sometimes|boolean',
            'is_system' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to access this organization.',
            ], 403);
        }

        $query = CustomRole::forOrganization($organizationId)
            ->withCount('users')
            ->with('creator:id,name,email');

        // Apply filters
        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                    ->orWhere('display_name', 'LIKE', "%{$search}%")
                    ->orWhere('description', 'LIKE', "%{$search}%");
            });
        }

        if ($request->has('is_active')) {
            $query->where('is_active', $request->is_active);
        }

        if ($request->has('is_system')) {
            if ($request->is_system) {
                $query->system();
            } else {
                $query->userDefined();
            }
        }

        // Apply sorting
        $sort = $request->input('sort', 'created_at');
        $order = $request->input('order', 'desc');
        $query->orderBy($sort, $order);

        // Paginate
        $perPage = $request->input('per_page', 15);
        $customRoles = $query->paginate($perPage);

        return response()->json([
            'data' => $customRoles->items()->map(function ($role) {
                return $this->formatCustomRoleResponse($role);
            }),
            'meta' => [
                'pagination' => [
                    'current_page' => $customRoles->currentPage(),
                    'per_page' => $customRoles->perPage(),
                    'total' => $customRoles->total(),
                    'total_pages' => $customRoles->lastPage(),
                ],
                'available_permissions' => CustomRole::getAvailablePermissions(),
                'permission_categories' => CustomRole::getPermissionCategories(),
            ],
            'links' => [
                'self' => $customRoles->url($customRoles->currentPage()),
                'next' => $customRoles->nextPageUrl(),
                'prev' => $customRoles->previousPageUrl(),
            ],
        ]);
    }

    /**
     * Store a newly created custom role
     */
    public function store(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('roles.create');

        $validator = Validator::make($request->all(), [
            'name' => [
                'required',
                'string',
                'max:255',
                'regex:/^[a-zA-Z0-9_\-\s]+$/',
                Rule::unique('custom_roles')->where('organization_id', $organizationId),
            ],
            'display_name' => 'sometimes|string|max:255',
            'description' => 'sometimes|string|max:1000',
            'permissions' => 'required|array|min:1',
            'permissions.*' => [
                'required',
                'string',
                Rule::in(CustomRole::getAvailablePermissions()),
            ],
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to create roles in this organization.',
            ], 403);
        }

        $customRole = CustomRole::create([
            'organization_id' => $organization->id,
            'name' => $request->name,
            'display_name' => $request->input('display_name'),
            'description' => $request->input('description'),
            'permissions' => $request->permissions,
            'is_system' => false, // User-created roles are never system roles
            'created_by' => $currentUser->id,
            'is_active' => $request->input('is_active', true),
        ]);

        // Log role creation
        $this->oAuthService->logAuthenticationEvent(
            $currentUser,
            'custom_role_created',
            $request,
            null,
            true,
            [
                'organization_id' => $organization->id,
                'custom_role_id' => $customRole->id,
                'role_name' => $customRole->name,
                'permissions_count' => count($customRole->permissions),
            ]
        );

        return response()->json([
            'data' => $this->formatCustomRoleResponse($customRole->load('creator')),
            'message' => 'Custom role created successfully',
        ], 201);
    }

    /**
     * Display the specified custom role
     */
    public function show(string $organizationId, string $id): JsonResponse
    {
        $this->authorize('roles.read');

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to access this organization.',
            ], 403);
        }

        $customRole = CustomRole::where('organization_id', $organizationId)
            ->withCount('users')
            ->with(['creator:id,name,email', 'users:id,name,email'])
            ->findOrFail($id);

        return response()->json([
            'data' => $this->formatCustomRoleResponse($customRole, true),
        ]);
    }

    /**
     * Update the specified custom role
     */
    public function update(Request $request, string $organizationId, string $id): JsonResponse
    {
        $this->authorize('roles.update');

        $validator = Validator::make($request->all(), [
            'name' => [
                'sometimes',
                'string',
                'max:255',
                'regex:/^[a-zA-Z0-9_\-\s]+$/',
                Rule::unique('custom_roles')->where('organization_id', $organizationId)->ignore($id),
            ],
            'display_name' => 'sometimes|string|max:255',
            'description' => 'sometimes|string|max:1000',
            'permissions' => 'sometimes|array|min:1',
            'permissions.*' => [
                'required',
                'string',
                Rule::in(CustomRole::getAvailablePermissions()),
            ],
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to update roles in this organization.',
            ], 403);
        }

        $customRole = CustomRole::where('organization_id', $organizationId)->findOrFail($id);

        // Check if it's a system role
        if ($customRole->isSystemRole()) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'System roles cannot be modified.',
            ], 403);
        }

        $updateData = $request->only(['name', 'display_name', 'description', 'permissions', 'is_active']);
        $customRole->update($updateData);

        // Log role update
        $this->oAuthService->logAuthenticationEvent(
            $currentUser,
            'custom_role_updated',
            $request,
            null,
            true,
            [
                'organization_id' => $organization->id,
                'custom_role_id' => $customRole->id,
                'role_name' => $customRole->name,
                'updated_fields' => array_keys($updateData),
            ]
        );

        return response()->json([
            'data' => $this->formatCustomRoleResponse($customRole->fresh(['creator', 'users'])),
            'message' => 'Custom role updated successfully',
        ]);
    }

    /**
     * Remove the specified custom role
     */
    public function destroy(string $organizationId, string $id): JsonResponse
    {
        $this->authorize('roles.delete');

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to delete roles in this organization.',
            ], 403);
        }

        $customRole = CustomRole::where('organization_id', $organizationId)
            ->withCount('users')
            ->findOrFail($id);

        // Check if role can be deleted
        if (! $customRole->canBeDeleted()) {
            $reason = $customRole->isSystemRole()
                ? 'System roles cannot be deleted.'
                : 'Role is assigned to users and cannot be deleted.';

            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => $reason,
            ], 409);
        }

        // Log role deletion
        $this->oAuthService->logAuthenticationEvent(
            $currentUser,
            'custom_role_deleted',
            request(),
            null,
            true,
            [
                'organization_id' => $organization->id,
                'custom_role_id' => $customRole->id,
                'role_name' => $customRole->name,
            ]
        );

        $customRole->delete();

        return response()->json([], 204);
    }

    /**
     * Get available permissions for custom roles
     */
    public function permissions(): JsonResponse
    {
        return response()->json([
            'data' => [
                'permissions' => CustomRole::getAvailablePermissions(),
                'categories' => CustomRole::getPermissionCategories(),
            ],
        ]);
    }

    /**
     * Assign users to a custom role
     */
    public function assignUsers(Request $request, string $organizationId, string $id): JsonResponse
    {
        $this->authorize('roles.assign');

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:1000',
            'user_ids.*' => 'required|integer|exists:users,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to assign roles in this organization.',
            ], 403);
        }

        $customRole = CustomRole::where('organization_id', $organizationId)->findOrFail($id);

        $userIds = $request->user_ids;
        $syncData = [];

        foreach ($userIds as $userId) {
            $syncData[$userId] = [
                'granted_at' => now(),
                'granted_by' => $currentUser->id,
            ];
        }

        $customRole->users()->syncWithoutDetaching($syncData);

        // Log role assignment
        $this->oAuthService->logAuthenticationEvent(
            $currentUser,
            'custom_role_users_assigned',
            $request,
            null,
            true,
            [
                'organization_id' => $organization->id,
                'custom_role_id' => $customRole->id,
                'role_name' => $customRole->name,
                'users_assigned' => count($userIds),
            ]
        );

        return response()->json([
            'message' => sprintf('Custom role assigned to %d users successfully', count($userIds)),
        ]);
    }

    /**
     * Remove users from a custom role
     */
    public function removeUsers(Request $request, string $organizationId, string $id): JsonResponse
    {
        $this->authorize('roles.assign');

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:1000',
            'user_ids.*' => 'required|integer|exists:users,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to manage roles in this organization.',
            ], 403);
        }

        $customRole = CustomRole::where('organization_id', $organizationId)->findOrFail($id);
        $userIds = $request->user_ids;

        $customRole->users()->detach($userIds);

        // Log role removal
        $this->oAuthService->logAuthenticationEvent(
            $currentUser,
            'custom_role_users_removed',
            $request,
            null,
            true,
            [
                'organization_id' => $organization->id,
                'custom_role_id' => $customRole->id,
                'role_name' => $customRole->name,
                'users_removed' => count($userIds),
            ]
        );

        return response()->json([
            'message' => sprintf('Custom role removed from %d users successfully', count($userIds)),
        ]);
    }

    /**
     * Format custom role response
     */
    private function formatCustomRoleResponse(CustomRole $customRole, bool $detailed = false): array
    {
        $data = [
            'id' => $customRole->id,
            'organization_id' => $customRole->organization_id,
            'name' => $customRole->name,
            'display_name' => $customRole->display_name,
            'description' => $customRole->description,
            'permissions' => $customRole->permissions ?? [],
            'permissions_count' => count($customRole->permissions ?? []),
            'is_system' => $customRole->is_system,
            'is_active' => $customRole->is_active,
            'users_count' => $customRole->users_count ?? 0,
            'can_be_deleted' => $customRole->canBeDeleted(),
            'created_at' => $customRole->created_at,
            'updated_at' => $customRole->updated_at,
        ];

        if ($customRole->relationLoaded('creator')) {
            $data['creator'] = $customRole->creator ? [
                'id' => $customRole->creator->id,
                'name' => $customRole->creator->name,
                'email' => $customRole->creator->email,
            ] : null;
        }

        if ($detailed && $customRole->relationLoaded('users')) {
            $data['users'] = $customRole->users->map(function ($user) {
                return [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'granted_at' => $user->pivot->granted_at,
                ];
            });
        }

        return $data;
    }
}
