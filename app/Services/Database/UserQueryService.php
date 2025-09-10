<?php

namespace App\Services\Database;

use App\Models\Organization;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Optimized database queries for user-related operations
 */
class UserQueryService
{
    /**
     * Get users with optimized relationship loading for analytics
     */
    public function getUsersWithAnalyticsData(Organization $organization, array $filters = []): Collection
    {
        $query = User::query()
            ->select([
                'users.id',
                'users.name',
                'users.email',
                'users.is_active',
                'users.created_at',
                'users.last_login_at',
                'users.mfa_methods',
                DB::raw('COUNT(DISTINCT user_applications.application_id) as application_count'),
                DB::raw('SUM(user_applications.login_count) as total_login_count'),
                DB::raw('MAX(user_applications.last_login_at) as latest_application_login'),
                DB::raw('COUNT(DISTINCT authentication_logs.id) as total_auth_events'),
            ])
            ->leftJoin('user_applications', 'users.id', '=', 'user_applications.user_id')
            ->leftJoin('authentication_logs', 'users.id', '=', 'authentication_logs.user_id')
            ->where('users.organization_id', $organization->id)
            ->with([
                'roles' => function ($query) {
                    $query->select('roles.id', 'roles.name', 'roles.guard_name');
                },
                'applications' => function ($query) {
                    $query->select('applications.id', 'applications.name')
                        ->withPivot(['granted_at', 'last_login_at', 'login_count']);
                },
            ])
            ->groupBy('users.id');

        // Apply filters efficiently
        if (! empty($filters['status'])) {
            $query->where('users.is_active', $filters['status'] === 'active');
        }

        if (! empty($filters['search'])) {
            $query->where(function (Builder $q) use ($filters) {
                $q->where('users.name', 'like', '%'.$filters['search'].'%')
                    ->orWhere('users.email', 'like', '%'.$filters['search'].'%');
            });
        }

        if (! empty($filters['role'])) {
            $query->whereExists(function (Builder $q) use ($filters) {
                $q->select(DB::raw(1))
                    ->from('model_has_roles')
                    ->join('roles', 'model_has_roles.role_id', '=', 'roles.id')
                    ->whereColumn('model_has_roles.model_id', 'users.id')
                    ->where('model_has_roles.model_type', User::class)
                    ->where('roles.name', $filters['role']);
            });
        }

        if (! empty($filters['created_from'])) {
            $query->where('users.created_at', '>=', $filters['created_from']);
        }

        if (! empty($filters['created_to'])) {
            $query->where('users.created_at', '<=', $filters['created_to']);
        }

        return $query->orderBy('users.created_at', 'desc')->get();
    }

    /**
     * Get user activity summary with optimized queries
     */
    public function getUserActivitySummary(Organization $organization, string $period = '30 days'): array
    {
        $startDate = now()->sub($period)->startOfDay();

        // Get basic user metrics
        $totalUsers = $organization->users()->count();
        $activeUsers = $organization->users()->where('is_active', true)->count();
        $newUsers = $organization->users()->where('created_at', '>=', $startDate)->count();
        $mfaUsers = $organization->users()->whereNotNull('mfa_methods')->count();

        // Get authentication metrics
        $authQuery = DB::table('authentication_logs')
            ->join('users', 'authentication_logs.user_id', '=', 'users.id')
            ->where('users.organization_id', $organization->id)
            ->where('authentication_logs.created_at', '>=', $startDate);

        $totalAuthEvents = $authQuery->count();
        $failedLogins = (clone $authQuery)->where('event', 'login_failed')->count();
        $recentlyActiveUsers = (clone $authQuery)->distinct('authentication_logs.user_id')->count('authentication_logs.user_id');

        // Get login count from user_applications
        $totalLogins = DB::table('user_applications')
            ->join('users', 'user_applications.user_id', '=', 'users.id')
            ->where('users.organization_id', $organization->id)
            ->sum('login_count') ?? 0;

        return [
            'total_users' => $totalUsers,
            'active_users' => $activeUsers,
            'new_users' => $newUsers,
            'mfa_enabled_users' => $mfaUsers,
            'recently_active_users' => $recentlyActiveUsers,
            'total_logins' => $totalLogins,
            'total_auth_events' => $totalAuthEvents,
            'failed_logins' => $failedLogins,
        ];
    }

    /**
     * Get top active users with single optimized query
     */
    public function getTopActiveUsers(Organization $organization, int $limit = 20, string $period = '30 days'): Collection
    {
        $startDate = now()->sub($period);

        return User::query()
            ->select([
                'users.id',
                'users.name',
                'users.email',
                'users.last_login_at',
                'users.mfa_methods',
                DB::raw('SUM(user_applications.login_count) as total_logins'),
                DB::raw('MAX(user_applications.last_login_at) as latest_login'),
                DB::raw('COUNT(DISTINCT user_applications.application_id) as app_count'),
            ])
            ->join('user_applications', 'users.id', '=', 'user_applications.user_id')
            ->where('users.organization_id', $organization->id)
            ->where('user_applications.last_login_at', '>=', $startDate)
            ->groupBy('users.id', 'users.name', 'users.email', 'users.last_login_at', 'users.mfa_methods')
            ->orderByDesc('total_logins')
            ->limit($limit)
            ->get()
            ->map(function ($user) {
                return [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'total_logins' => $user->total_logins,
                    'latest_login' => $user->latest_login,
                    'app_count' => $user->app_count,
                    'mfa_enabled' => ! empty($user->mfa_methods),
                    'last_login_at' => $user->last_login_at,
                ];
            });
    }

    /**
     * Bulk user operations with optimized queries
     */
    public function bulkUpdateUserStatus(Organization $organization, array $userIds, bool $isActive): int
    {
        return User::query()
            ->where('organization_id', $organization->id)
            ->whereIn('id', $userIds)
            ->update(['is_active' => $isActive]);
    }

    /**
     * Get user permission matrix efficiently
     */
    public function getUserPermissionMatrix(Organization $organization): array
    {
        // Get users with their roles and permissions using Laravel relationships
        $users = $organization->users()
            ->with([
                'roles' => function ($query) {
                    $query->select('roles.id', 'roles.name')
                        ->with(['permissions:id,name,group_name']);
                },
            ])
            ->select('id', 'name', 'email')
            ->orderBy('name')
            ->get();

        // Process results into structured matrix using collections
        return $users->map(function ($user) {
            $roleData = [];
            $permissionData = [];

            $user->roles->each(function ($role) use (&$roleData, &$permissionData) {
                $roleData[$role->name] = true;

                $role->permissions->groupBy('group_name')->each(function ($permissions, $group) use (&$permissionData) {
                    foreach ($permissions as $permission) {
                        $permissionData[$group][$permission->name] = true;
                    }
                });
            });

            return [
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
                'roles' => $roleData,
                'permissions' => $permissionData,
            ];
        })->toArray();
    }

    /**
     * Search users with optimized full-text search
     */
    public function searchUsersOptimized(Organization $organization, string $searchTerm, int $limit = 50): Collection
    {
        return User::query()
            ->select([
                'users.id',
                'users.name',
                'users.email',
                'users.is_active',
                'users.created_at',
                DB::raw('COUNT(DISTINCT user_applications.application_id) as app_count'),
                DB::raw('MAX(user_applications.last_login_at) as latest_login'),
            ])
            ->leftJoin('user_applications', 'users.id', '=', 'user_applications.user_id')
            ->where('users.organization_id', $organization->id)
            ->where(function (Builder $query) use ($searchTerm) {
                $query->where('users.name', 'like', '%'.$searchTerm.'%')
                    ->orWhere('users.email', 'like', '%'.$searchTerm.'%');
            })
            ->groupBy('users.id', 'users.name', 'users.email', 'users.is_active', 'users.created_at')
            ->orderByDesc('latest_login')
            ->limit($limit)
            ->get();
    }

    /**
     * Get authentication trends with optimized query
     */
    public function getAuthenticationTrends(Organization $organization, int $days = 30): array
    {
        $startDate = now()->subDays($days)->startOfDay();

        // Get authentication logs using Laravel collections for processing
        $authLogs = DB::table('authentication_logs')
            ->join('users', 'authentication_logs.user_id', '=', 'users.id')
            ->where('users.organization_id', $organization->id)
            ->where('authentication_logs.created_at', '>=', $startDate)
            ->select('authentication_logs.*')
            ->get();

        // Process trends using Laravel collections
        $trends = $authLogs->groupBy(function ($log) {
            return Carbon::parse($log->created_at)->format('Y-m-d');
        })
            ->map(function ($dayLogs, $date) {
                return [
                    'date' => $date,
                    'successful_logins' => $dayLogs->where('event', 'login_success')->count(),
                    'failed_logins' => $dayLogs->where('event', 'login_failed')->count(),
                    'unique_users' => $dayLogs->unique('user_id')->count(),
                    'unique_ips' => $dayLogs->unique('ip_address')->count(),
                ];
            })
            ->sortByDesc('date')
            ->values();

        return $trends->map(function ($row) {
            $totalAttempts = $row->successful_logins + $row->failed_logins;

            return [
                'date' => $row->date,
                'successful_logins' => (int) $row->successful_logins,
                'failed_logins' => (int) $row->failed_logins,
                'unique_users' => (int) $row->unique_users,
                'unique_ips' => (int) $row->unique_ips,
                'success_rate' => $totalAttempts > 0
                    ? round(($row->successful_logins / $totalAttempts) * 100, 2)
                    : 0,
            ];
        })->toArray();
    }
}
