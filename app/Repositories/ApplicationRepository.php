<?php

namespace App\Repositories;

use App\Models\Application;
use App\Models\Organization;
use App\Repositories\Contracts\ApplicationRepositoryInterface;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

/**
 * Application repository implementation
 */
class ApplicationRepository extends BaseRepository implements ApplicationRepositoryInterface
{
    /**
     * ApplicationRepository constructor.
     */
    public function __construct(Application $model)
    {
        parent::__construct($model);
    }

    /**
     * Find application by client ID
     */
    public function findByClientId(string $clientId): ?Application
    {
        return $this->model
            ->with(['organization'])
            ->where('client_id', $clientId)
            ->first();
    }

    /**
     * Get applications for organization with pagination
     */
    public function getOrganizationApplications(Organization $organization, array $filters = [], int $perPage = 15): LengthAwarePaginator
    {
        $query = $this->model
            ->where('organization_id', $organization->id)
            ->with(['organization', 'ssoConfiguration']);

        // Apply filters
        if (isset($filters['status'])) {
            $query->where('is_active', $filters['status'] === 'active');
        }

        if (isset($filters['search'])) {
            $query->where('name', 'like', '%'.$filters['search'].'%');
        }

        if (isset($filters['grant_type'])) {
            $query->whereJsonContains('allowed_grant_types', $filters['grant_type']);
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
     * Get applications with user counts
     */
    public function getWithUserCounts(Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->withCount('users')
            ->with(['organization'])
            ->get();
    }

    /**
     * Get active applications for organization
     */
    public function getActiveApplications(Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->where('is_active', true)
            ->with(['organization'])
            ->orderBy('name')
            ->get();
    }

    /**
     * Find application with relationships
     */
    public function findWithRelationships(int $id): ?Application
    {
        return $this->model
            ->with([
                'organization',
                'users',
                'ssoConfiguration',
                'ssoSessions' => function ($query) {
                    $query->latest()->limit(10);
                },
            ])
            ->find($id);
    }

    /**
     * Get applications with SSO configurations
     */
    public function getWithSSOConfigurations(Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->with(['ssoConfiguration'])
            ->whereHas('ssoConfiguration')
            ->get();
    }

    /**
     * Search applications by name
     */
    public function searchApplications(string $query, Organization $organization, int $limit = 10): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->where('name', 'like', '%'.$query.'%')
            ->limit($limit)
            ->get();
    }

    /**
     * Get application analytics
     */
    public function getApplicationAnalytics(Application $application, string $startDate, string $endDate): array
    {
        // Get user access analytics using Eloquent relationships
        $totalUsers = $application->users()->count();
        $newUsers = $application->users()
            ->wherePivot('created_at', '>=', $startDate)
            ->wherePivot('created_at', '<=', $endDate)
            ->count();

        // Get aggregated statistics using collections
        $userPivotData = $application->users()
            ->withPivot('login_count')
            ->get()
            ->pluck('pivot.login_count')
            ->filter(); // Remove null values

        $totalLogins = $userPivotData->sum();
        $avgLogins = $userPivotData->avg();

        // Get SSO session analytics using Eloquent relationships
        $totalSessions = $application->ssoSessions()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->count();

        $activeSessions = $application->ssoSessions()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->whereNull('logged_out_at')
            ->count();

        $endedSessions = $application->ssoSessions()
            ->whereBetween('created_at', [$startDate, $endDate])
            ->whereNotNull('logged_out_at')
            ->count();

        return [
            'users' => [
                'total' => $totalUsers,
                'new' => $newUsers,
                'avg_logins_per_user' => round($avgLogins ?? 0, 2),
                'total_logins' => $totalLogins ?? 0,
            ],
            'sso' => [
                'total_sessions' => $totalSessions,
                'active_sessions' => $activeSessions,
                'ended_sessions' => $endedSessions,
            ],
        ];
    }

    /**
     * Get applications created in date range
     */
    public function getApplicationsCreatedBetween(string $startDate, string $endDate, Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->whereBetween('created_at', [$startDate, $endDate])
            ->orderBy('created_at', 'desc')
            ->get();
    }

    /**
     * Check if client ID is available
     */
    public function isClientIdAvailable(string $clientId, ?int $excludeId = null): bool
    {
        $query = $this->model->where('client_id', $clientId);

        if ($excludeId) {
            $query->where('id', '!=', $excludeId);
        }

        return ! $query->exists();
    }

    /**
     * Get applications by grant type
     */
    public function getByGrantType(string $grantType, Organization $organization): Collection
    {
        return $this->model
            ->where('organization_id', $organization->id)
            ->whereJsonContains('allowed_grant_types', $grantType)
            ->get();
    }

    /**
     * Get application usage statistics
     */
    public function getUsageStatistics(Application $application): array
    {
        // Get user statistics using Eloquent relationships
        $totalUsers = $application->users()->count();

        // Get statistics using collections
        $userPivotData = $application->users()
            ->withPivot('login_count', 'last_login_at')
            ->get();

        $loginCounts = $userPivotData->pluck('pivot.login_count')->filter();
        $totalLogins = $loginCounts->sum();
        $avgLogins = $loginCounts->avg();
        $lastLogin = $userPivotData->pluck('pivot.last_login_at')->filter()->max();

        // Get recent activity (last 30 days) using Eloquent
        $recentActivity = $application->users()
            ->wherePivot('last_login_at', '>=', now()->subDays(30))
            ->count();

        return [
            'total_users' => $totalUsers,
            'total_logins' => $totalLogins ?? 0,
            'last_login' => $lastLogin,
            'avg_logins_per_user' => round($avgLogins ?? 0, 2),
            'active_users_last_30_days' => $recentActivity,
            'has_sso' => $application->hasSSOEnabled(),
        ];
    }
}
