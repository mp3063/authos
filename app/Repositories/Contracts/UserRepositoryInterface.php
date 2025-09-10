<?php

namespace App\Repositories\Contracts;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

/**
 * User repository interface
 */
interface UserRepositoryInterface extends BaseRepositoryInterface
{
    /**
     * Find user with applications loaded
     */
    public function findWithApplications(int $id): ?User;

    /**
     * Find user with roles loaded
     */
    public function findWithRoles(int $id): ?User;

    /**
     * Find user with complete relationships
     */
    public function findWithRelationships(int $id): ?User;

    /**
     * Get users for organization with pagination
     */
    public function getOrganizationUsers(Organization $organization, array $filters = [], int $perPage = 15): LengthAwarePaginator;

    /**
     * Get users with specific role
     */
    public function getUsersWithRole(string $roleName, Organization $organization): Collection;

    /**
     * Get users with application access
     */
    public function getUsersWithApplicationAccess(int $applicationId, Organization $organization): Collection;

    /**
     * Search users by email or name
     */
    public function searchUsers(string $query, Organization $organization, int $limit = 10): Collection;

    /**
     * Get active users for organization
     */
    public function getActiveUsers(Organization $organization): Collection;

    /**
     * Get users created in date range
     */
    public function getUsersCreatedBetween(string $startDate, string $endDate, Organization $organization): Collection;

    /**
     * Get users with last login in date range
     */
    public function getUsersWithLastLoginBetween(string $startDate, string $endDate, Organization $organization): Collection;

    /**
     * Bulk update users
     */
    public function bulkUpdateUsers(array $userIds, array $data, Organization $organization): int;

    /**
     * Get user count by status
     */
    public function getUserCountByStatus(Organization $organization): array;

    /**
     * Find user by email in organization
     */
    public function findByEmailInOrganization(string $email, Organization $organization): ?User;

    /**
     * Find users by IDs within organization
     */
    public function findByIdsInOrganization(array $userIds, Organization $organization): Collection;
}
