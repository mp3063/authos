<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\ListRequest;
use App\Http\Requests\User\StoreUserRequest;
use App\Http\Requests\User\UpdateUserRequest;
use App\Models\User;
use App\Models\Application;
use App\Models\SSOSession;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
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

        $response = $this->formatUserResponse($user);
        $response['message'] = 'User created successfully';
        
        return response()->json($response, 201);
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

        return response()->json($this->formatUserResponse($user, true));
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

        $response = $this->formatUserResponse($user->fresh());
        $response['message'] = 'User updated successfully';
        
        return response()->json($response);
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
        
        // Remove user relationships to prevent foreign key constraints
        $user->applications()->detach();
        $user->roles()->detach();
        $user->ssoSessions()->update([
            'logged_out_at' => now(),
            'logged_out_by' => auth()->id()
        ]);

        // Log user deletion event
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'user_deleted_by_admin',
            request(),
            null
        );

        // Handle foreign key constraints before deleting user
        // Nullify invitations where user is inviter, accepted_by, or cancelled_by
        \App\Models\Invitation::where('inviter_id', $user->id)->update(['inviter_id' => null]);
        \App\Models\Invitation::where('accepted_by', $user->id)->update(['accepted_by' => null]);
        \App\Models\Invitation::where('cancelled_by', $user->id)->update(['cancelled_by' => null]);
        
        // Delete authentication logs
        \App\Models\AuthenticationLog::where('user_id', $user->id)->delete();
        
        // Delete oauth access tokens
        \DB::table('oauth_access_tokens')->where('user_id', $user->id)->delete();
        
        // Delete related SSOSessions
        $user->ssoSessions()->delete();
        
        // Nullify CustomRole created_by references
        \App\Models\CustomRole::where('created_by', $user->id)->update(['created_by' => null]);
        
        // Delete user's tokens/sessions (in case some remain)
        $user->tokens()->delete();
        
        // Detach user from applications and roles
        $user->applications()->detach();
        $user->roles()->detach();

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
        $applications = $user->applications()
            ->withPivot(['last_login_at', 'login_count', 'permissions'])
            ->get();

        return response()->json([
            'data' => $applications->map(function ($app) {
                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'client_id' => $app->client_id,
                    'permissions' => $app->pivot->permissions ?? [],
                    'last_accessed_at' => $app->pivot->last_login_at, // Use last_login_at as fallback
                    'access_count' => $app->pivot->login_count ?? 0, // Use login_count as fallback
                    'last_login_at' => $app->pivot->last_login_at,
                    'login_count' => $app->pivot->login_count ?? 0,
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

        return response()->json([
            'message' => 'Application access revoked successfully',
        ], 200);
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
            'role_id' => 'required|integer|exists:roles,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = User::findOrFail($id);
        $role = Role::findOrFail($request->role_id);

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

        return response()->json([
            'message' => 'Role removed successfully',
        ], 200);
    }

    /**
     * Get user's active sessions
     */
    public function sessions(string $id): JsonResponse
    {
        $this->authorize('users.read');

        $user = User::findOrFail($id);
        $sessions = $user->ssoSessions()
            ->with('application')
            ->active()
            ->get();

        return response()->json([
            'data' => $sessions->map(function ($session) {
                return [
                    'id' => $session->id,
                    'application' => [
                        'id' => $session->application->id,
                        'name' => $session->application->name,
                    ],
                    'ip_address' => $session->ip_address,
                    'user_agent' => $session->user_agent,
                    'last_activity_at' => $session->last_activity_at,
                    'expires_at' => $session->expires_at,
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
        $activeSessions = $user->ssoSessions()->active()->get();
        $revokedCount = $activeSessions->count();
        
        // Log out each session  
        $adminUser = auth()->user() ?? User::find(1);
        foreach ($activeSessions as $session) {
            $session->update([
                'logged_out_at' => now(),
                'logged_out_by' => $adminUser->id,
            ]);
        }

        // Log session revocation
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'all_sessions_revoked_by_admin',
            request(),
            null
        );

        return response()->json([
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
        $session = $user->ssoSessions()->where('id', $sessionId)->first();

        if (!$session) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'Session not found.',
            ], 404);
        }

        // Use the admin user making the request
        $adminUser = auth()->user() ?? User::find(1);
        
        // Force the logout with explicit update
        $session->update([
            'logged_out_at' => now(),
            'logged_out_by' => $adminUser->id,
        ]);

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
            'organization_id' => $user->organization_id,
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

        if ($detailed) {
            // Add detailed fields for show() method
            $permissions = collect();
            if ($user->relationLoaded('roles')) {
                foreach ($user->roles as $role) {
                    if ($role->relationLoaded('permissions')) {
                        $permissions = $permissions->merge($role->permissions);
                    }
                }
            }
            
            $data['permissions'] = $permissions->pluck('name')->unique()->values();
            $data['last_login_at'] = $user->last_login_at ?? null;
            $data['applications_count'] = $user->applications_count ?? $user->applications()->count();
            $data['sessions_count'] = $user->sso_sessions_count ?? $user->ssoSessions()->active()->count();

            if ($user->relationLoaded('applications')) {
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
        }

        return $data;
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
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $userIds = $request->input('user_ids');
        $action = $request->input('action');
        $currentUser = $request->user();

        // Get users from the same organization as the current user
        $users = User::whereIn('id', $userIds)
            ->where('organization_id', $currentUser->organization_id)
            ->get();

        if ($users->count() !== count($userIds)) {
            return response()->json([
                'error' => 'access_denied',
                'error_description' => 'Some users not found or not accessible.',
            ], 403);
        }

        $affectedCount = 0;
        
        foreach ($users as $user) {
            // Don't allow bulk operations on self
            if ($user->id === $currentUser->id) {
                continue;
            }

            switch ($action) {
                case 'activate':
                    $user->update(['is_active' => true]);
                    $affectedCount++;
                    break;
                case 'deactivate':
                    $user->update(['is_active' => false]);
                    $affectedCount++;
                    break;
                case 'delete':
                    $user->delete();
                    $affectedCount++;
                    break;
            }
        }

        // Log the bulk operation
        Log::info('Bulk user operation performed', [
            'operator_id' => $currentUser->id,
            'organization_id' => $currentUser->organization_id,
            'action' => $action,
            'affected_count' => $affectedCount,
            'user_ids' => $userIds
        ]);

        return response()->json([
            'message' => 'Bulk operation completed successfully',
            'affected_count' => $affectedCount,
        ], 200);
    }
}