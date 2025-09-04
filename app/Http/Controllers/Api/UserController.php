<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\ListRequest;
use App\Http\Requests\User\StoreUserRequest;
use App\Http\Requests\User\UpdateUserRequest;
use App\Models\User;
use App\Models\Application;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Spatie\Permission\Models\Role;

class UserController extends Controller
{
    protected OAuthService $oAuthService;

    public function __construct(OAuthService $oAuthService)
    {
        $this->oAuthService = $oAuthService;
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

        return response()->json([
            'data' => $users->getCollection()->map(function ($user) {
                return $this->formatUserResponse($user);
            }),
            'meta' => [
                'pagination' => [
                    'current_page' => $users->currentPage(),
                    'per_page' => $users->perPage(),
                    'total' => $users->total(),
                    'total_pages' => $users->lastPage(),
                ],
            ],
            'links' => [
                'self' => $users->url($users->currentPage()),
                'next' => $users->nextPageUrl(),
                'prev' => $users->previousPageUrl(),
            ],
        ]);
    }

    /**
     * Store a newly created user
     */
    public function store(StoreUserRequest $request): JsonResponse
    {

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'organization_id' => $request->organization_id,
            'profile' => $request->input('profile', []),
            'email_verified_at' => now(), // Admin-created users are verified by default
        ]);

        // Assign roles
        $roles = $request->getRoles();
        $user->syncRoles($roles);

        // Log user creation event
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'user_created_by_admin',
            $request,
            null
        );

        return response()->json([
            'data' => $this->formatUserResponse($user),
            'message' => 'User created successfully',
        ], 201);
    }

    /**
     * Display the specified user
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::with(['roles', 'organization', 'applications'])->findOrFail($id);

        return response()->json([
            'data' => $this->formatUserResponse($user, true),
        ]);
    }

    /**
     * Update the specified user
     */
    public function update(UpdateUserRequest $request, string $id): JsonResponse
    {
        $user = User::findOrFail($id);

        $updateData = $request->only(['name', 'email', 'organization_id', 'profile', 'is_active']);
        
        if ($request->has('password')) {
            $updateData['password'] = Hash::make($request->password);
        }

        if ($request->has('profile')) {
            $updateData['profile'] = array_merge($user->profile ?? [], $request->profile);
        }

        $user->update($updateData);

        // Log user update event
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'user_updated_by_admin',
            $request,
            null
        );

        return response()->json([
            'data' => $this->formatUserResponse($user->fresh()),
            'message' => 'User updated successfully',
        ]);
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
            return response()->json([
                'error' => 'authorization_failed',
                'error_description' => 'Cannot delete your own account.',
            ], 403);
        }

        // Revoke all user tokens before deletion
        $user->tokens()->delete();

        // Log user deletion event
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'user_deleted_by_admin',
            request(),
            null
        );

        $user->delete();

        return response()->json([], 204);
    }

    /**
     * Get user's applications
     */
    public function applications(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);
        $applications = $user->applications()->withPivot(['last_login_at', 'login_count'])->get();

        return response()->json([
            'data' => $applications->map(function ($app) {
                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'client_id' => $app->client_id,
                    'last_login_at' => $app->pivot->last_login_at,
                    'login_count' => $app->pivot->login_count,
                    'is_active' => $app->is_active,
                ];
            }),
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
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = User::findOrFail($id);
        $application = Application::findOrFail($request->application_id);

        // Check if access already exists
        if ($user->applications()->where('application_id', $application->id)->exists()) {
            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => 'User already has access to this application.',
            ], 409);
        }

        $user->applications()->attach($application->id, [
            'granted_at' => now(),
            'login_count' => 0,
        ]);

        return response()->json([
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
        $application = Application::findOrFail($applicationId);

        if (!$user->applications()->where('application_id', $application->id)->exists()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'User does not have access to this application.',
            ], 404);
        }

        $user->applications()->detach($application->id);

        return response()->json([], 204);
    }

    /**
     * Get user's roles
     */
    public function roles(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);

        return response()->json([
            'data' => $user->roles->map(function ($role) {
                return [
                    'id' => $role->id,
                    'name' => $role->name,
                    'display_name' => $role->display_name ?? ucfirst($role->name),
                    'permissions' => $role->permissions->pluck('name'),
                ];
            }),
        ]);
    }

    /**
     * Assign role to user
     */
    public function assignRole(Request $request, string $id): JsonResponse
    {
        $this->authorize('roles.assign');

        $validator = Validator::make($request->all(), [
            'role' => 'required|string|exists:roles,name',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = User::findOrFail($id);
        $role = Role::where('name', $request->role)->first();

        if ($user->hasRole($role)) {
            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => 'User already has this role.',
            ], 409);
        }

        $user->assignRole($role);

        return response()->json([
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
        $role = Role::findOrFail($roleId);

        if (!$user->hasRole($role)) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'User does not have this role.',
            ], 404);
        }

        $user->removeRole($role);

        return response()->json([], 204);
    }

    /**
     * Get user's active sessions
     */
    public function sessions(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);
        $tokens = $user->tokens()->where('expires_at', '>', now())->get();

        return response()->json([
            'data' => $tokens->map(function ($token) {
                return [
                    'id' => $token->id,
                    'name' => $token->name,
                    'scopes' => $token->scopes,
                    'created_at' => $token->created_at,
                    'expires_at' => $token->expires_at,
                    'last_used_at' => $token->last_used_at,
                ];
            }),
        ]);
    }

    /**
     * Revoke all user sessions
     */
    public function revokeSessions(string $id): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $revokedCount = $user->tokens()->count();
        $user->tokens()->delete();

        // Log session revocation
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'all_sessions_revoked_by_admin',
            request(),
            null
        );

        return response()->json([
            'message' => "Revoked {$revokedCount} active sessions",
        ]);
    }

    /**
     * Revoke specific user session
     */
    public function revokeSession(string $id, string $sessionId): JsonResponse
    {
        $this->authorize('users.update');

        $user = User::findOrFail($id);
        $token = $user->tokens()->where('id', $sessionId)->first();

        if (!$token) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'Session not found.',
            ], 404);
        }

        $this->oAuthService->revokeToken($token->id);

        return response()->json([
            'message' => 'Session revoked successfully',
        ]);
    }

    /**
     * Format user response
     */
    private function formatUserResponse(User $user, bool $detailed = false): array
    {
        $data = [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'email_verified_at' => $user->email_verified_at,
            'profile' => $user->profile ?? [],
            'mfa_enabled' => $user->hasMfaEnabled(),
            'mfa_methods' => $user->mfa_methods ?? [],
            'is_active' => $user->is_active ?? true,
            'organization' => $user->organization ? [
                'id' => $user->organization->id,
                'name' => $user->organization->name,
                'slug' => $user->organization->slug,
            ] : null,
            'roles' => $user->roles->map(function ($role) {
                return [
                    'id' => $role->id,
                    'name' => $role->name,
                    'display_name' => $role->display_name ?? ucfirst($role->name),
                ];
            }),
            'created_at' => $user->created_at,
            'updated_at' => $user->updated_at,
        ];

        if ($detailed && $user->relationLoaded('applications')) {
            $data['applications'] = $user->applications->map(function ($app) {
                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'client_id' => $app->client_id,
                    'last_login_at' => $app->pivot->last_login_at ?? null,
                    'login_count' => $app->pivot->login_count ?? 0,
                ];
            });
        }

        return $data;
    }
}