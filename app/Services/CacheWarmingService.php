<?php

namespace App\Services;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class CacheWarmingService
{
    /**
     * Warm up all critical caches.
     */
    public function warmAll(): array
    {
        $results = [];

        if (config('performance.cache.warming.enabled', true)) {
            $results['organizations'] = $this->warmOrganizationCaches();
            $results['permissions'] = $this->warmPermissionCaches();
            $results['applications'] = $this->warmApplicationCaches();
            $results['statistics'] = $this->warmStatisticsCaches();
        }

        Log::info('Cache warming completed', $results);

        return $results;
    }

    /**
     * Warm up organization-related caches.
     */
    public function warmOrganizationCaches(): int
    {
        $count = 0;
        $ttl = config('performance.cache.ttl.organization_settings', 1800);

        Organization::chunk(100, function ($organizations) use (&$count, $ttl) {
            foreach ($organizations as $org) {
                // Cache organization settings
                Cache::remember(
                    "org:settings:{$org->id}",
                    $ttl,
                    fn () => $org->settings ?? []
                );

                // Cache organization user count
                Cache::remember(
                    "org:user_count:{$org->id}",
                    $ttl,
                    fn () => $org->organizationUsers()->count()
                );

                // Cache organization application count
                Cache::remember(
                    "org:app_count:{$org->id}",
                    $ttl,
                    fn () => $org->applications()->count()
                );

                $count++;
            }
        });

        return $count;
    }

    /**
     * Warm up permission and role caches.
     */
    public function warmPermissionCaches(): int
    {
        $count = 0;
        $ttl = config('performance.cache.ttl.roles_permissions', 1800);

        // Cache all permissions
        Cache::remember(
            'permissions:all',
            $ttl,
            fn () => Permission::all()
        );

        // Cache all roles with permissions
        Cache::remember(
            'roles:all',
            $ttl,
            fn () => Role::with('permissions')->get()
        );

        // Cache permissions by guard
        foreach (['web', 'api'] as $guard) {
            Cache::remember(
                "permissions:guard:{$guard}",
                $ttl,
                fn () => Permission::where('guard_name', $guard)->get()
            );

            Cache::remember(
                "roles:guard:{$guard}",
                $ttl,
                fn () => Role::where('guard_name', $guard)->with('permissions')->get()
            );

            $count += 2;
        }

        return $count + 2;
    }

    /**
     * Warm up application-related caches.
     */
    public function warmApplicationCaches(): int
    {
        $count = 0;
        $ttl = config('performance.cache.ttl.application_config', 3600);

        Application::with('organization')->chunk(100, function ($applications) use (&$count, $ttl) {
            foreach ($applications as $app) {
                // Cache application configuration
                Cache::remember(
                    "app:config:{$app->id}",
                    $ttl,
                    fn () => [
                        'id' => $app->id,
                        'name' => $app->name,
                        'client_id' => $app->client_id,
                        'redirect_uris' => $app->redirect_uris,
                        'settings' => $app->settings,
                        'organization_id' => $app->organization_id,
                    ]
                );

                // Cache application by client_id
                Cache::remember(
                    "app:client_id:{$app->client_id}",
                    $ttl,
                    fn () => $app
                );

                $count++;
            }
        });

        return $count;
    }

    /**
     * Warm up statistics caches.
     */
    public function warmStatisticsCaches(): int
    {
        $ttl = config('performance.cache.ttl.analytics_data', 300);

        // Cache global statistics
        Cache::remember('stats:total_users', $ttl, fn () => User::count());
        Cache::remember('stats:total_organizations', $ttl, fn () => Organization::count());
        Cache::remember('stats:total_applications', $ttl, fn () => Application::count());
        Cache::remember('stats:active_users', $ttl, fn () => User::where('is_active', true)->count());

        // Cache today's authentication logs count
        Cache::remember(
            'stats:auth_logs_today',
            $ttl,
            fn () => DB::table('authentication_logs')
                ->whereDate('created_at', today())
                ->count()
        );

        return 5;
    }

    /**
     * Warm up caches for a specific organization.
     */
    public function warmOrganization(int $organizationId): bool
    {
        try {
            $org = Organization::find($organizationId);
            if (! $org) {
                return false;
            }

            $ttl = config('performance.cache.ttl.organization_settings', 1800);

            // Organization settings
            Cache::put("org:settings:{$organizationId}", $org->settings ?? [], $ttl);

            // User count
            Cache::put("org:user_count:{$organizationId}", $org->organizationUsers()->count(), $ttl);

            // Application count
            Cache::put("org:app_count:{$organizationId}", $org->applications()->count(), $ttl);

            // Active applications
            Cache::put(
                "org:active_apps:{$organizationId}",
                $org->applications()->where('is_active', true)->get(),
                $ttl
            );

            // Organization roles
            Cache::put(
                "org:roles:{$organizationId}",
                $org->roles()->with('permissions')->get(),
                $ttl
            );

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to warm organization cache', [
                'organization_id' => $organizationId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Warm up caches for a specific user.
     */
    public function warmUser(int $userId): bool
    {
        try {
            $user = User::with(['roles.permissions', 'organization'])->find($userId);
            if (! $user) {
                return false;
            }

            $ttl = config('performance.cache.ttl.user_permissions', 600);

            // User permissions
            Cache::put(
                "user:permissions:{$userId}",
                $user->getAllPermissions()->pluck('name'),
                $ttl
            );

            // User roles
            Cache::put(
                "user:roles:{$userId}",
                $user->roles->pluck('name'),
                $ttl
            );

            // User profile
            $profileTtl = config('performance.cache.ttl.user_profile', 300);
            Cache::put(
                "user:profile:{$userId}",
                [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'organization_id' => $user->organization_id,
                    'mfa_enabled' => $user->hasMfaEnabled(),
                ],
                $profileTtl
            );

            return true;
        } catch (\Exception $e) {
            Log::error('Failed to warm user cache', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Clear all warmed caches.
     */
    public function clearAll(): void
    {
        $patterns = [
            'org:*',
            'app:*',
            'user:*',
            'permissions:*',
            'roles:*',
            'stats:*',
        ];

        foreach ($patterns as $pattern) {
            Cache::forget($pattern);
        }

        Log::info('All warmed caches cleared');
    }
}
