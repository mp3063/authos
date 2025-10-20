<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Spatie\Permission\PermissionRegistrar;

class AuthorizationServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void {}

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Override Gate authorization to handle team context
        Gate::before(function ($user, $ability) {
            // Super admins have access to all abilities
            if ($user->isSuperAdmin()) {
                return true;
            }

            // Only process for API requests with organization context
            if (! request()->is('api/*') || ! $user->organization_id) {
                return null; // Let normal authorization proceed
            }

            // Ensure team context is set
            $user->setPermissionsTeamId($user->organization_id);
            app(PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);

            // Force refresh permissions to prevent cache issues
            $user->unsetRelation('permissions');
            $user->unsetRelation('roles');

            // Check if user has permission within their organization
            try {
                if ($user->hasPermissionTo($ability)) {
                    return true;
                }
            } catch (PermissionDoesNotExist $e) {
                // Permission doesn't exist, return false instead of throwing
                return false;
            }

            // Fallback: Manual check for organization-scoped permissions
            $permissions = $user->getAllPermissions();
            $orgScopedPermission = "$ability (org:$user->organization_id)";

            foreach ($permissions as $permission) {
                if ($permission->name === $ability || $permission->name === $orgScopedPermission) {
                    return true;
                }
            }

            // Let normal authorization proceed (may deny)
            return null;
        });
    }
}
