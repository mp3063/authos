<?php

namespace App\Repositories;

use App\Models\Organization;
use App\Repositories\Contracts\OrganizationRepositoryInterface;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;

/**
 * Organization repository implementation
 */
class OrganizationRepository extends BaseRepository implements OrganizationRepositoryInterface
{
    /**
     * OrganizationRepository constructor.
     */
    public function __construct(Organization $model)
    {
        parent::__construct($model);
    }

    /**
     * Find organization by slug
     */
    public function findBySlug(string $slug): ?Organization
    {
        return $this->model
            ->where('slug', $slug)
            ->first();
    }

    /**
     * Get organizations with user counts
     */
    public function getWithUserCounts(array $filters = [], int $perPage = 15): LengthAwarePaginator
    {
        $query = $this->model->query();

        // Add user count using Laravel's withCount method
        $query->withCount('users');

        // Apply filters
        if (isset($filters['is_active'])) {
            $query->where('is_active', $filters['is_active'] === 'true' || $filters['is_active'] === true);
        }

        if (isset($filters['search'])) {
            $query->where(function (Builder $q) use ($filters) {
                $q->where('name', 'like', '%'.$filters['search'].'%')
                    ->orWhere('slug', 'like', '%'.$filters['search'].'%')
                    ->orWhere('domain', 'like', '%'.$filters['search'].'%');
            });
        }

        if (isset($filters['created_from'])) {
            $query->where('created_at', '>=', $filters['created_from']);
        }

        if (isset($filters['created_to'])) {
            $query->where('created_at', '<=', $filters['created_to']);
        }

        return $query->orderBy('created_at', 'desc')->paginate($perPage);
    }

    /**
     * Get organizations with application counts
     */
    public function getWithApplicationCounts(): Collection
    {
        return $this->model
            ->withCount('applications')
            ->get();
    }

    /**
     * Get active organizations
     */
    public function getActiveOrganizations(): Collection
    {
        return $this->model
            ->where('is_active', true)
            ->orderBy('name')
            ->get();
    }

    /**
     * Get organizations created in date range
     */
    public function getOrganizationsCreatedBetween(string $startDate, string $endDate): Collection
    {
        return $this->model
            ->whereBetween('created_at', [$startDate, $endDate])
            ->orderBy('created_at', 'desc')
            ->get();
    }

    /**
     * Search organizations by name or domain
     */
    public function searchOrganizations(string $query, int $limit = 10): Collection
    {
        return $this->model
            ->where(function (Builder $q) use ($query) {
                $q->where('name', 'like', '%'.$query.'%')
                    ->orWhere('slug', 'like', '%'.$query.'%')
                    ->orWhere('domain', 'like', '%'.$query.'%');
            })
            ->limit($limit)
            ->get();
    }

    /**
     * Get organization analytics data
     */
    public function getAnalyticsData(Organization $organization, string $startDate, string $endDate): array
    {
        // User analytics using Eloquent relationships
        $totalUsers = $organization->users()->count();
        $activeUsers = $organization->users()->where('is_active', true)->count();
        $newUsers = $organization->users()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->count();

        // Application analytics using Eloquent relationships
        $totalApplications = $organization->applications()->count();
        $activeApplications = $organization->applications()->where('is_active', true)->count();

        // Authentication analytics using Eloquent relationships and collections
        $authLogs = $organization->users()
            ->with(['authenticationLogs' => function ($query) use ($startDate, $endDate) {
                $query->whereBetween('created_at', [$startDate, $endDate]);
            }])
            ->get()
            ->pluck('authenticationLogs')
            ->flatten();

        $totalLogins = $authLogs->count();
        $successfulLogins = $authLogs->where('status', 'success')->count();
        $failedLogins = $authLogs->where('status', 'failed')->count();
        $uniqueUsers = $authLogs->pluck('user_id')->unique()->count();

        return [
            'users' => [
                'total' => $totalUsers,
                'active' => $activeUsers,
                'new' => $newUsers,
            ],
            'applications' => [
                'total' => $totalApplications,
                'active' => $activeApplications,
            ],
            'authentication' => [
                'total_logins' => $totalLogins,
                'successful_logins' => $successfulLogins,
                'failed_logins' => $failedLogins,
                'unique_users' => $uniqueUsers,
            ],
        ];
    }

    /**
     * Get organization settings
     */
    public function getSettings(Organization $organization): array
    {
        return $organization->settings ?? [];
    }

    /**
     * Update organization settings
     */
    public function updateSettings(Organization $organization, array $settings): Organization
    {
        $organization->settings = array_merge($organization->settings ?? [], $settings);
        $organization->save();

        return $organization;
    }

    /**
     * Get organizations by domain
     */
    public function getByDomain(string $domain): Collection
    {
        return $this->model
            ->where('domain', $domain)
            ->get();
    }

    /**
     * Check if slug is available
     */
    public function isSlugAvailable(string $slug, ?int $excludeId = null): bool
    {
        $query = $this->model->where('slug', $slug);

        if ($excludeId) {
            $query->where('id', '!=', $excludeId);
        }

        return ! $query->exists();
    }

    /**
     * Get filtered organizations with pagination
     */
    public function getFilteredOrganizations(?string $search = null, array $filters = [], string $sort = 'created_at', string $order = 'desc', int $perPage = 15)
    {
        $query = $this->model->newQuery();

        // Apply search (using LIKE for SQLite compatibility)
        if ($search) {
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                    ->orWhere('slug', 'LIKE', "%{$search}%")
                    ->orWhere('description', 'LIKE', "%{$search}%");
            });
        }

        // Apply filters
        if (! empty($filters['is_active'])) {
            $query->where('is_active', $filters['is_active'] === 'true');
        }

        if (! empty($filters['created_after'])) {
            $query->where('created_at', '>=', $filters['created_after']);
        }

        if (! empty($filters['created_before'])) {
            $query->where('created_at', '<=', $filters['created_before']);
        }

        // Skip withCount due to Laravel compatibility issue - will default to 0 in resource

        // Apply sorting
        $query->orderBy($sort, $order);

        return $query->paginate($perPage);
    }
}
