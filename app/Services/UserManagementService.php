<?php

namespace App\Services;

use App\Models\Organization;
use App\Models\User;
use App\Repositories\Contracts\UserRepositoryInterface;
use App\Services\Contracts\UserManagementServiceInterface;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Spatie\Permission\Models\Role as SpatieRole;

class UserManagementService extends BaseService implements UserManagementServiceInterface
{
    protected AuthenticationLogService $authLogService;

    protected UserRepositoryInterface $userRepository;

    public function __construct(AuthenticationLogService $authLogService, UserRepositoryInterface $userRepository)
    {
        $this->authLogService = $authLogService;
        $this->userRepository = $userRepository;
    }

    /**
     * Create a new user
     */
    public function createUser(array $userData, Organization $organization, ?string $roleId = null): User
    {
        $data = [
            'name' => $userData['name'],
            'email' => $userData['email'],
            'password' => Hash::make($userData['password']),
            'organization_id' => $organization->id,
            'profile' => $userData['profile'] ?? [],
            'email_verified_at' => now(), // Admin-created users are verified by default
        ];

        $user = User::create($data);

        // Set permissions team context for the organization
        $user->setPermissionsTeamId($organization->id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($organization->id);

        // Assign roles if provided
        // Guard is handled by User model's getDefaultGuardName() method
        if (! empty($userData['roles'])) {
            $user->syncRoles($userData['roles']);
        } elseif ($roleId) {
            $user->assignRole($roleId);
        }

        // Log user creation event
        if (request()) {
            $this->authLogService->logAuthenticationEvent(
                $user,
                'user_created_by_admin',
                [],
                request()
            );
        }

        return $user;
    }

    /**
     * Get paginated users for an organization
     */
    public function getUsersForOrganization(Organization $organization, array $filters = [], int $perPage = 15): \Illuminate\Contracts\Pagination\LengthAwarePaginator
    {
        return $this->userRepository->getOrganizationUsers($organization, $filters, $perPage);
    }

    /**
     * Update an existing user
     */
    public function updateUser(User $user, array $userData): User
    {
        $updateData = collect($userData)->only(['name', 'email', 'organization_id', 'profile', 'is_active'])->toArray();

        if (isset($userData['password'])) {
            $updateData['password'] = Hash::make($userData['password']);
        }

        if (isset($userData['profile'])) {
            $updateData['profile'] = array_merge($user->profile ?? [], $userData['profile']);
        }

        $user->update($updateData);

        // Log user update event
        if (request()) {
            $this->authLogService->logAuthenticationEvent(
                $user,
                'user_updated_by_admin',
                [],
                request()
            );
        }

        return $user->fresh();
    }

    /**
     * Delete a user with all related data cleanup
     */
    public function deleteUser(User $user): bool
    {
        return DB::transaction(function () use ($user) {
            // Revoke all user tokens before deletion
            $user->tokens()->delete();

            // Remove user relationships to prevent foreign key constraints
            $user->applications()->detach();
            $user->roles()->detach();
            $user->ssoSessions()->update([
                'logged_out_at' => now(),
                'logged_out_by' => auth()->id(),
            ]);

            // Log user deletion event before cleanup
            if (request()) {
                $this->authLogService->logAuthenticationEvent(
                    $user,
                    'user_deleted_by_admin',
                    [],
                    request()
                );
            }

            // Handle foreign key constraints before deleting user
            $this->cleanupUserRelations($user);

            // Delete the user
            return $user->delete();
        });
    }

    /**
     * Grant application access to user
     */
    public function grantApplicationAccess(
        User $user,
        int $applicationId,
        array $permissions = [],
        ?int $grantedBy = null
    ): bool {
        // Check if access already exists - if it does, update permissions instead
        $exists = $user->applications()->where('application_id', $applicationId)->exists();

        if ($exists) {
            // Update existing permissions - don't json_encode, pivot cast handles it
            $user->applications()->updateExistingPivot($applicationId, [
                'permissions' => $permissions,
                'granted_by' => $grantedBy,
                'updated_at' => now(),
            ]);
        } else {
            // Create new access - don't json_encode, pivot cast handles it
            $user->applications()->attach($applicationId, [
                'permissions' => $permissions,
                'granted_at' => now(),
                'granted_by' => $grantedBy,
                'login_count' => 0,
            ]);
        }

        // Log the action
        $this->authLogService->logAuthenticationEvent($user, 'application_access_granted', [
            'application_id' => $applicationId,
            'permissions' => $permissions,
            'granted_by' => $grantedBy,
        ]);

        return true;
    }

    /**
     * Revoke application access from user
     */
    public function revokeApplicationAccess(User $user, int $applicationId, ?int $revokedBy = null): bool
    {
        if (! $user->applications()->where('application_id', $applicationId)->exists()) {
            return false;
        }

        $user->applications()->detach($applicationId);

        // Log the action
        $this->authLogService->logAuthenticationEvent($user, 'application_access_revoked', [
            'application_id' => $applicationId,
            'revoked_by' => $revokedBy,
        ]);

        return true;
    }

    /**
     * Assign role to user
     */
    public function assignRole(User $user, string $roleId): bool
    {
        $role = SpatieRole::findOrFail($roleId);

        if ($user->hasRole($role)) {
            return false;
        }

        // Guard is handled by User model's getDefaultGuardName() method
        $user->assignRole($role);

        return true;
    }

    /**
     * Remove role from user
     */
    public function removeRole(User $user, string $roleId): bool
    {
        $role = SpatieRole::findOrFail($roleId);

        if (! $user->hasRole($role)) {
            return false;
        }

        $user->removeRole($role);

        return true;
    }

    /**
     * Get user's active OAuth tokens (sessions)
     */
    public function getUserSessions(User $user): EloquentCollection
    {
        // Get OAuth access tokens (Passport) for this user
        return $user->tokens()
            ->where('revoked', false)
            ->orderBy('created_at', 'desc')
            ->get();
    }

    /**
     * Revoke all user OAuth tokens (sessions)
     */
    public function revokeAllUserSessions(User $user): int
    {
        // Get all active OAuth tokens for this user
        $activeTokens = $user->tokens()->where('revoked', false)->get();
        $revokedCount = $activeTokens->count();

        // Revoke each token
        foreach ($activeTokens as $token) {
            $token->revoke();
        }

        // Log session revocation
        if (request()) {
            \App\Models\AuthenticationLog::create([
                'user_id' => $user->id,
                'event' => 'all_sessions_revoked',
                'success' => true,
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'details' => [],
            ]);
        }

        return $revokedCount;
    }

    /**
     * Revoke specific user OAuth token (session)
     */
    public function revokeUserSession(User $user, string $sessionId): bool
    {
        // Find the specific OAuth token
        $token = $user->tokens()->where('id', $sessionId)->first();

        if (! $token) {
            return false;
        }

        // Revoke the token
        $token->revoke();

        // Log session revocation
        if (request()) {
            \App\Models\AuthenticationLog::create([
                'user_id' => $user->id,
                'event' => 'session_revoked',
                'success' => true,
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'details' => ['token_id' => $sessionId],
            ]);
        }

        return true;
    }

    /**
     * Perform bulk operations on users
     */
    public function performBulkOperation(array $userIds, string $action, User $currentUser): array
    {
        // Get users from the same organization as the current user
        $users = $this->userRepository->findByIdsInOrganization($userIds, $currentUser->organization);

        if ($users->count() !== count($userIds)) {
            throw new \InvalidArgumentException('Some users not found or not accessible.');
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
                    $this->deleteUser($user);
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
            'user_ids' => $userIds,
        ]);

        return [
            'affected_count' => $affectedCount,
            'total_requested' => count($userIds),
        ];
    }

    /**
     * Clean up user relations before deletion
     */
    private function cleanupUserRelations(User $user): void
    {
        // Nullify invitations where user is inviter, accepted_by, or cancelled_by
        \App\Models\Invitation::where('inviter_id', $user->id)->update(['inviter_id' => null]);
        \App\Models\Invitation::where('accepted_by', $user->id)->update(['accepted_by' => null]);
        \App\Models\Invitation::where('cancelled_by', $user->id)->update(['cancelled_by' => null]);

        // Delete authentication logs
        \App\Models\AuthenticationLog::where('user_id', $user->id)->delete();

        // Delete oauth access tokens
        DB::table('oauth_access_tokens')->where('user_id', $user->id)->delete();

        // Delete related SSOSessions
        $user->ssoSessions()->delete();

        // Nullify CustomRole created_by references
        \App\Models\CustomRole::where('created_by', $user->id)->update(['created_by' => null]);

        // Delete user's tokens/sessions (in case some remain)
        $user->tokens()->delete();

        // Detach user from applications and roles
        $user->applications()->detach();
        $user->roles()->detach();
    }

    /**
     * Format user response data
     */
    public function formatUserResponse(User $user, bool $detailed = false): array
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
            $data['applications_count'] = $user->relationLoaded('applications')
                ? $user->applications->count()
                : $user->applications()->count();
            $data['sessions_count'] = $user->relationLoaded('ssoSessions')
                ? $user->ssoSessions->where('is_active', true)->count()
                : $user->ssoSessions()->active()->count();

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
     * Format user applications response
     */
    public function formatUserApplicationsResponse(Collection $applications): array
    {
        return $applications->map(function ($app) {
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
        })->toArray();
    }

    /**
     * Format user OAuth tokens (sessions) response
     */
    public function formatUserSessionsResponse(Collection $sessions): array
    {
        return $sessions->map(function ($token) {
            // Decode scopes from JSON if it's a string
            $scopes = $token->scopes;
            if (is_string($scopes)) {
                $scopes = json_decode($scopes, true) ?? [];
            }

            return [
                'id' => $token->id,
                'name' => $token->name,
                'scopes' => $scopes ?? [],
                'created_at' => $token->created_at?->toISOString(),
                'expires_at' => $token->expires_at?->toISOString(),
                'last_used_at' => $token->updated_at?->toISOString(),
                'revoked' => (bool) $token->revoked,
            ];
        })->toArray();
    }

    /**
     * Format user roles response
     */
    public function formatUserRolesResponse(Collection $roles): array
    {
        return $roles->map(function ($role) {
            return [
                'id' => $role->id,
                'name' => $role->name,
                'display_name' => $role->display_name ?? ucfirst($role->name),
                'permissions' => $role->permissions->pluck('name'),
            ];
        })->toArray();
    }
}
