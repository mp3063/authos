<?php

namespace App\Services;

use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Repositories\Contracts\OrganizationRepositoryInterface;
use App\Services\Contracts\OrganizationAnalyticsServiceInterface;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class OrganizationAnalyticsService extends BaseService implements OrganizationAnalyticsServiceInterface
{
    protected OrganizationRepositoryInterface $organizationRepository;

    public function __construct(OrganizationRepositoryInterface $organizationRepository)
    {
        $this->organizationRepository = $organizationRepository;
    }

    /**
     * Get comprehensive analytics for an organization
     */
    public function getAnalytics(Organization $organization, string $period = '30d'): array
    {
        // Get date range based on period
        $dateRange = $this->getDateRangeForPeriod($period);
        $applicationIds = $organization->applications()->pluck('id');

        return [
            'summary' => $this->getSummaryMetrics($organization, $applicationIds, $dateRange),
            'user_growth' => $this->getUserGrowthMetrics($organization, $period),
            'login_activity' => $this->getLoginActivityMetrics($organization, $period),
            'top_applications' => $this->getTopApplicationsMetrics($organization, $period),
            'security_events' => $this->getSecurityMetrics($organization, $period),
        ];
    }

    /**
     * Get summary metrics for an organization
     */
    public function getSummaryMetrics(Organization $organization, Collection $applicationIds, array $dateRange): array
    {
        $authLogs = $this->getAuthLogQuery($applicationIds, $dateRange);

        $totalLogins = $authLogs->clone()->where('event', 'login_success')->count();
        $uniqueUsers = $authLogs->clone()->where('event', 'login_success')->distinct('user_id')->count('user_id');

        return [
            'total_users' => $uniqueUsers,
            'active_users' => $uniqueUsers, // Using unique users as active users for this period
            'total_applications' => $organization->applications()->count(),
            'total_logins_today' => $totalLogins,
        ];
    }

    /**
     * Get user growth metrics for an organization
     */
    public function getUserGrowthMetrics(Organization $organization, string $period = '30d'): array
    {
        $dateRange = $this->calculateDateRange($period, 'UTC');
        $applicationIds = $organization->applications()->pluck('id');

        // Get user registrations over time within the organization
        $userGrowth = User::whereHas('applications', function ($query) use ($applicationIds) {
            $query->whereIn('application_id', $applicationIds);
        })
            ->whereBetween('created_at', [$dateRange['start'], $dateRange['end']])
            ->selectRaw('DATE(created_at) as date, COUNT(*) as count')
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->map(function ($item) {
                return [
                    'date' => $item->date,
                    'count' => $item->count,
                ];
            });

        return [
            'period' => $period,
            'growth_data' => $userGrowth,
            'total_new_users' => $userGrowth->sum('count'),
        ];
    }

    /**
     * Get daily login activity
     */
    public function getLoginActivity(Collection $applicationIds, array $dateRange, string $timezone): Collection
    {
        $authLogs = $this->getAuthLogQuery($applicationIds, $dateRange);

        return $authLogs->clone()
            ->where('event', 'login_success')
            ->select(
                DB::raw(
                    config('database.default') === 'sqlite' ?
                      'DATE(created_at) as login_date' :
                      "DATE_TRUNC('day', created_at AT TIME ZONE '$timezone') as login_date"
                ),
                DB::raw('COUNT(*) as count')
            )
            ->groupByRaw(
                config('database.default') === 'sqlite' ?
                  'DATE(created_at)' :
                  "DATE_TRUNC('day', created_at AT TIME ZONE '$timezone')"
            )
            ->orderByRaw(
                config('database.default') === 'sqlite' ?
                  'DATE(created_at)' :
                  "DATE_TRUNC('day', created_at AT TIME ZONE '$timezone')"
            )
            ->get()
            ->map(function ($item) {
                return [
                    'date' => Carbon::parse($item->login_date)->format('Y-m-d'),
                    'count' => $item->count,
                ];
            });
    }

    /**
     * Get application usage metrics for an organization
     */
    public function getApplicationUsage(Organization $organization, array $dateRange): Collection
    {
        return $organization->applications()
            ->with([
                'users' => function ($query) use ($dateRange) {
                    $query->withPivot(['last_login_at', 'login_count'])
                        ->wherePivot('last_login_at', '>=', $dateRange['start']);
                },
            ])
            ->get()
            ->map(function ($app) {
                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'total_users' => $app->users->count(),
                    'active_users' => $app->users->count(),
                    'total_logins' => $app->users->sum('pivot.login_count'),
                ];
            });
    }

    /**
     * Get security metrics for an organization
     */
    public function getSecurityMetrics(Organization $organization, string $period = '30d'): array
    {
        $dateRange = $this->calculateDateRange($period, 'UTC');
        $applicationIds = $organization->applications()->pluck('id');
        $authLogs = $this->getAuthLogQuery($applicationIds, $dateRange);
        $failedLogins = $authLogs->clone()->where('event', 'login_failed')->count();

        return [
            'period' => $period,
            'mfa_enabled_users' => User::whereHas('applications', function ($query) use ($applicationIds) {
                $query->whereIn('application_id', $applicationIds);
            })->whereNotNull('mfa_methods')->count(),
            'failed_login_attempts' => $failedLogins,
            'suspicious_activity' => $authLogs->clone()
                ->whereIn('event', ['login_failed', 'token_revoked', 'logout'])
                ->where('success', false)
                ->count(),
        ];
    }

    /**
     * Get top users by login activity
     */
    public function getTopUsers(Collection $applicationIds, array $dateRange, int $limit = 10): Collection
    {
        return User::whereHas('applications', function ($query) use ($applicationIds, $dateRange) {
            $query->whereIn('application_id', $applicationIds)
                ->wherePivot('last_login_at', '>=', $dateRange['start']);
        })->with([
            'applications' => function ($query) use ($applicationIds) {
                $query->whereIn('application_id', $applicationIds)
                    ->withPivot(['last_login_at', 'login_count']);
            },
        ])
            ->get()
            ->map(function ($user) {
                $totalLogins = $user->applications->sum('pivot.login_count');
                $lastLogin = $user->applications->max('pivot.last_login_at');

                return [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'total_logins' => $totalLogins,
                    'last_login_at' => $lastLogin,
                ];
            })
            ->sortByDesc('total_logins')
            ->take($limit)
            ->values();
    }

    /**
     * Get organization users with metrics
     */
    public function getOrganizationUsers(Organization $organization, array $filters = []): Collection
    {
        $query = User::whereHas('applications', function ($query) use ($organization) {
            $query->where('organization_id', $organization->id);
        })->with([
            'roles',
            'applications' => function ($query) use ($organization) {
                $query->where('organization_id', $organization->id)
                    ->withPivot(['last_login_at', 'login_count', 'granted_at']);
            },
        ]);

        $this->applyUserFilters($query, $filters);

        return $query->get();
    }

    /**
     * Apply filters to user query
     */
    private function applyUserFilters($query, array $filters): void
    {
        if (! empty($filters['search'])) {
            $search = $filters['search'];
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%$search%")
                    ->orWhere('email', 'LIKE', "%$search%");
            });
        }

        if (! empty($filters['role'])) {
            $query->whereHas('roles', function ($q) use ($filters) {
                $q->where('name', $filters['role']);
            });
        }

        if (isset($filters['is_active'])) {
            $query->where('is_active', $filters['is_active']);
        }
    }

    /**
     * Calculate date range based on period
     */
    private function calculateDateRange(string $period, string $timezone): array
    {
        $endDate = now($timezone);
        $startDate = match ($period) {
            '24h' => $endDate->copy()->subHours(24),
            '7d' => $endDate->copy()->subDays(7),
            '90d' => $endDate->copy()->subDays(90),
            default => $endDate->copy()->subDays(30), // Covers '30d' and any other periods
        };

        return [
            'start' => $startDate,
            'end' => $endDate,
        ];
    }

    /**
     * Get base authentication log query
     */
    private function getAuthLogQuery(Collection $applicationIds, array $dateRange): Builder
    {
        return AuthenticationLog::whereHas('user.applications', function ($query) use ($applicationIds) {
            $query->whereIn('application_id', $applicationIds);
        })->whereBetween('created_at', [$dateRange['start'], $dateRange['end']]);
    }

    public function getUserActivityMetrics(Organization $organization, string $startDate, string $endDate): array
    {
        $dateRange = [
            'start' => Carbon::parse($startDate),
            'end' => Carbon::parse($endDate),
        ];
        $applicationIds = $organization->applications()->pluck('id');

        $totalUsers = User::whereHas('applications', function ($query) use ($applicationIds) {
            $query->whereIn('application_id', $applicationIds);
        })->count();

        $activeUsers = $this->getTopUsers($applicationIds, $dateRange, 1000)->count();

        return [
            'total_users' => $totalUsers,
            'active_users' => $activeUsers,
            'activity_trend' => $this->getLoginActivity($applicationIds, $dateRange, 'UTC'),
        ];
    }

    public function getApplicationUsageMetrics(Organization $organization, string $startDate, string $endDate): array
    {
        $dateRange = [
            'start' => Carbon::parse($startDate),
            'end' => Carbon::parse($endDate),
        ];

        $usageMetrics = $this->getApplicationUsage($organization, $dateRange);

        return [
            'applications' => $usageMetrics,
            'total_applications' => $usageMetrics->count(),
            'most_active_application' => $usageMetrics->sortByDesc('total_logins')->first(),
        ];
    }

    public function getAuthenticationMetrics(Organization $organization, string $startDate, string $endDate): array
    {
        $dateRange = [
            'start' => Carbon::parse($startDate),
            'end' => Carbon::parse($endDate),
        ];
        $applicationIds = $organization->applications()->pluck('id');
        $authLogs = $this->getAuthLogQuery($applicationIds, $dateRange);

        $successfulLogins = $authLogs->clone()->where('event', 'login_success')->count();
        $failedLogins = $authLogs->clone()->where('event', 'login_failed')->count();
        $totalLogins = $successfulLogins + $failedLogins;

        return [
            'total_logins' => $totalLogins,
            'successful_logins' => $successfulLogins,
            'failed_logins' => $failedLogins,
            'success_rate' => $totalLogins > 0 ? round(($successfulLogins / $totalLogins) * 100, 2) : 0,
            'login_trend' => $this->getLoginActivity($applicationIds, $dateRange, 'UTC'),
        ];
    }

    public function getTopApplications(Organization $organization, int $limit = 10): array
    {
        $dateRange = $this->calculateDateRange('30d', 'UTC');
        $applications = $this->getApplicationUsage($organization, $dateRange)
            ->sortByDesc('total_logins')
            ->take($limit)
            ->values();

        return [
            'applications' => $applications,
            'total_count' => $applications->count(),
        ];
    }

    /**
     * Get filtered organizations with pagination
     */
    public function getFilteredOrganizations(?string $search = null, array $filters = [], string $sort = 'created_at', string $order = 'desc', int $perPage = 15)
    {
        return $this->organizationRepository->getFilteredOrganizations($search, $filters, $sort, $order, $perPage);
    }

    /**
     * Get date range for a given period
     */
    private function getDateRangeForPeriod(string $period): array
    {
        $end = Carbon::now();

        $start = match ($period) {
            '24h' => $end->copy()->subHours(24),
            '7d' => $end->copy()->subDays(7),
            '30d' => $end->copy()->subDays(30),
            '90d' => $end->copy()->subDays(90),
            '1y' => $end->copy()->subYear(),
            default => $end->copy()->subDays(30),
        };

        return [
            'start' => $start,
            'end' => $end,
        ];
    }

    /**
     * Get login activity metrics
     */
    private function getLoginActivityMetrics(Organization $organization, string $period): array
    {
        $dateRange = $this->getDateRangeForPeriod($period);

        return [
            'daily_logins' => $this->getDailyLoginCounts($organization, $dateRange),
            'peak_hours' => $this->getPeakLoginHours($organization, $dateRange),
        ];
    }

    /**
     * Get top applications metrics
     */
    private function getTopApplicationsMetrics(Organization $organization, string $period): array
    {
        return [
            'most_used' => $this->getTopApplications($organization, 10),
            'usage_trends' => [],
        ];
    }

    /**
     * Get daily login counts
     */
    private function getDailyLoginCounts(Organization $organization, array $dateRange): array
    {
        return []; // Simplified for now
    }

    /**
     * Get peak login hours
     */
    private function getPeakLoginHours(Organization $organization, array $dateRange): array
    {
        return []; // Simplified for now
    }

    /**
     * Get application metrics for a specific organization
     */
    public function getApplicationMetrics(int $organizationId, string $period = '30d', ?int $applicationId = null): array
    {
        $organization = Organization::findOrFail($organizationId);
        $dateRange = $this->getDateRangeForPeriod($period);

        if ($applicationId) {
            // Get metrics for specific application
            $application = $organization->applications()->findOrFail($applicationId);

            return $this->getSpecificApplicationMetrics($application, $dateRange);
        }

        // Get metrics for all applications in the organization - return just the applications array
        $usageMetrics = $this->getApplicationUsage($organization, $dateRange);

        return $usageMetrics->toArray();
    }

    /**
     * Get metrics for a specific application
     */
    private function getSpecificApplicationMetrics($application, array $dateRange): array
    {
        $usersCount = $application->users()->count();
        $activeUsersCount = $application->users()
            ->wherePivot('last_login_at', '>=', $dateRange['start'])
            ->count();

        return [
            'id' => $application->id,
            'name' => $application->name,
            'client_id' => $application->client_id,
            'total_users' => $usersCount,
            'active_users' => $activeUsersCount,
            'total_logins' => $application->users()->sum('pivot.login_count') ?? 0,
            'created_at' => $application->created_at,
            'updated_at' => $application->updated_at,
        ];
    }
}
