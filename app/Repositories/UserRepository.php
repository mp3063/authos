<?php

namespace App\Repositories;

use App\Models\Organization;
use App\Models\User;
use App\Repositories\Contracts\UserRepositoryInterface;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;

/**
 * User repository implementation
 */
class UserRepository extends BaseRepository implements UserRepositoryInterface
{
    /**
     * UserRepository constructor.
     */
    public function __construct(User $model)
    {
        parent::__construct($model);
    }

    /**
     * Find user with applications loaded
     */
    public function findWithApplications(int $id): ?User
    {
        $result = $this->model
            ->with(['applications', 'organization'])
            ->find($id);

        return $result instanceof User ? $result : null;
    }

    /**
     * Find user with roles loaded
     */
    public function findWithRoles(int $id): ?User
    {
        $result = $this->model
            ->with(['roles.permissions', 'organization'])
            ->find($id);

        return $result instanceof User ? $result : null;
    }

    /**
     * Find user with complete relationships
     */
    public function findWithRelationships(int $id): ?User
    {
        $result = $this->model
            ->with([
                'organization',
                'roles.permissions',
                'applications',
                'authenticationLogs' => function ($query) {
                    $query->latest()->limit(10);
                },
            ])
            ->find($id);

        return $result instanceof User ? $result : null;
    }

    /**
     * Get users for organization with pagination
     */
    public function getOrganizationUsers(Organization $organization, array $filters = [], int $perPage = 15): LengthAwarePaginator
    {
        $query = $this->model
            ->with(['roles', 'organization'])
            ->where('organization_id', $organization->id);

        // Apply filters
        if (isset($filters['status'])) {
            $query->where('is_active', $filters['status'] === 'active');
        }

        if (isset($filters['role'])) {
            $query->whereHas('roles', function (Builder $q) use ($filters) {
                $q->where('name', $filters['role']);
            });
        }

        if (isset($filters['search'])) {
            $query->where(function (Builder $q) use ($filters) {
                $q->where('name', 'like', '%'.$filters['search'].'%')
                    ->orWhere('email', 'like', '%'.$filters['search'].'%');
            });
        }

        if (isset($filters['created_from'])) {
            $query->where('created_at', '>=', $filters['created_from']);
        }

        if (isset($filters['created_to'])) {
            $query->where('created_at', '<=', $filters['created_to']);
        }

        if (isset($filters['last_login_from'])) {
            $query->where('last_login_at', '>=', $filters['last_login_from']);
        }

        if (isset($filters['last_login_to'])) {
            $query->where('last_login_at', '<=', $filters['last_login_to']);
        }

        return $query->orderBy('created_at', 'desc')->paginate($perPage);
    }

    /**
     * Get users with specific role
     */
    public function getUsersWithRole(string $roleName, Organization $organization): Collection
    {
        return $this->model
            ->with(['roles', 'organization'])
            ->where('organization_id', $organization->id)
            ->whereHas('roles', function (Builder $query) use ($roleName) {
                $query->where('name', $roleName);
            })
            ->get();
    }

    /**
     * Get users with application access
     */
    public function getUsersWithApplicationAccess(int $applicationId, Organization $organization): Collection
    {
        return $this->model
            ->with(['applications', 'organization'])
            ->where('organization_id', $organization->id)
            ->whereHas('applications', function (Builder $query) use ($applicationId) {
                $query->where('id', $applicationId);
            })
            ->get();
    }

    /**
     * Search users by email or name
     */
    public function searchUsers(string $query, Organization $organization, int $limit = 10): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->where(function (Builder $q) use ($query) {
                $q->where('name', 'like', '%'.$query.'%')
                    ->orWhere('email', 'like', '%'.$query.'%');
            })
            ->limit($limit)
            ->get();
    }

    /**
     * Get active users for organization
     */
    public function getActiveUsers(Organization $organization): Collection
    {
        return $this->model
            ->with(['roles', 'organization'])
            ->where('organization_id', $organization->id)
            ->where('is_active', true)
            ->get();
    }

    /**
     * Get users created in date range
     */
    public function getUsersCreatedBetween(string $startDate, string $endDate, Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->whereBetween('created_at', [$startDate, $endDate])
            ->get();
    }

    /**
     * Get users with last login in date range
     */
    public function getUsersWithLastLoginBetween(string $startDate, string $endDate, Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->whereBetween('last_login_at', [$startDate, $endDate])
            ->get();
    }

    /**
     * Bulk update users
     */
    public function bulkUpdateUsers(array $userIds, array $data, Organization $organization): int
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->whereIn('id', $userIds)
            ->update($data);
    }

    /**
     * Get user count by status
     */
    public function getUserCountByStatus(Organization $organization): array
    {
        $counts = $this->model
            ->where('organization_id', $organization->id)
            ->selectRaw('is_active, COUNT(*) as count')
            ->groupBy('is_active')
            ->get()
            ->keyBy('is_active')
            ->map(function ($item) {
                return $item->count;
            });

        return [
            'active' => $counts->get(1, 0),
            'inactive' => $counts->get(0, 0),
            'total' => $counts->sum(),
        ];
    }

    /**
     * Find user by email in organization
     */
    public function findByEmailInOrganization(string $email, Organization $organization): ?User
    {
        $result = $this->model
            ->where('organization_id', $organization->id)
            ->where('email', $email)
            ->first();

        return $result instanceof User ? $result : null;
    }

    /**
     * Find users by IDs within organization
     */
    public function findByIdsInOrganization(array $userIds, Organization $organization): Collection
    {
        return $this->model
            ->whereIn('id', $userIds)
            ->where('organization_id', $organization->id)
            ->get();
    }
}
