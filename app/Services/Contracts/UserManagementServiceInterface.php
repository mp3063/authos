<?php

namespace App\Services\Contracts;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

/**
 * Interface for user management service operations
 */
interface UserManagementServiceInterface extends BaseServiceInterface
{
    /**
     * Get paginated users for an organization
     */
    public function getUsersForOrganization(Organization $organization, array $filters = [], int $perPage = 15): LengthAwarePaginator;

    /**
     * Create a new user with role assignment
     */
    public function createUser(array $userData, Organization $organization, ?string $roleId = null): User;

    /**
     * Update user information
     */
    public function updateUser(User $user, array $userData): User;

    /**
     * Soft delete user and handle cascading relationships
     */
    public function deleteUser(User $user): bool;

    /**
     * Assign role to user
     */
    public function assignRole(User $user, string $roleId): bool;

    /**
     * Remove role from user
     */
    public function removeRole(User $user, string $roleId): bool;

    /**
     * Grant application access to user
     */
    public function grantApplicationAccess(User $user, int $applicationId): bool;

    /**
     * Revoke application access from user
     */
    public function revokeApplicationAccess(User $user, int $applicationId): bool;

    /**
     * Get user's active sessions
     */
    public function getUserSessions(User $user): Collection;

    /**
     * Revoke all user sessions
     */
    public function revokeAllUserSessions(User $user): int;

    /**
     * Revoke specific user session
     */
    public function revokeUserSession(User $user, string $sessionId): bool;
}
