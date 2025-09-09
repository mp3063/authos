<?php

namespace App\Http\Middleware;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class EnforceOrganizationBoundary
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        // Skip for non-authenticated requests
        if (! Auth::check()) {
            return $next($request);
        }

        $user = Auth::user();

        // Debug user roles
        \Log::info('Organization boundary middleware debug', [
            'user_id' => $user->id,
            'user_organization' => $user->organization_id,
            'path' => $request->path(),
            'roles_web' => $user->getRoleNames('web')->toArray(),
            'roles_api' => $user->getRoleNames('api')->toArray(),
            'has_super_admin_web' => $user->hasRole('Super Admin', 'web'),
            'has_super_admin_api' => $user->hasRole('Super Admin', 'api'),
        ]);

        // Skip for super admins (they can access all organizations)
        if ($user->hasRole('super-admin') || $user->hasRole('Super Admin') ||
            $user->hasRole('super-admin', 'api') || $user->hasRole('Super Admin', 'api')) {
            \Log::info('Super admin detected, allowing access');

            return $next($request);
        }

        \Log::info('Not a super admin, checking organization boundaries');

        // Check if the route has organization ID parameter
        $organizationId = $request->route('organizationId');
        $applicationId = $request->route('applicationId');
        $userId = $request->route('userId');

        // For user and application routes, the 'id' parameter refers to those resources, not organization
        $routeName = $request->route()->getName();
        $routeUri = $request->route()->uri();

        if (str_contains($routeUri, 'users/{id}')) {
            $userId = $request->route('id');
        } elseif (str_contains($routeUri, 'applications/{id}')) {
            $applicationId = $request->route('id');
        } elseif (str_contains($routeUri, 'organizations/{id}')) {
            $organizationId = $request->route('id');
        }

        // Validate organization access
        if ($organizationId && ! $this->canAccessOrganization($user, $organizationId)) {
            $this->logViolationAttempt($user, 'organization', $organizationId, $request);

            return response()->json([
                'error' => 'Access denied',
                'message' => 'Access denied to this organization',
            ], 403);
        }

        // Validate application access
        if ($applicationId && ! $this->canAccessApplication($user, $applicationId)) {
            $this->logViolationAttempt($user, 'application', $applicationId, $request);

            // Return 404 to not leak information about application existence
            return response()->json([
                'error' => 'Not found',
                'message' => 'The requested resource was not found.',
            ], 404);
        }

        // Validate user access (for user management endpoints)
        if ($userId && ! $this->canAccessUser($user, $userId)) {
            $this->logViolationAttempt($user, 'user', $userId, $request);

            // Return 404 to not leak information about user existence
            return response()->json([
                'error' => 'Not found',
                'message' => 'The requested resource was not found.',
            ], 404);
        }

        return $next($request);
    }

    /**
     * Check if user can access the specified organization
     */
    private function canAccessOrganization(User $user, int $organizationId): bool
    {
        // Users can only access their own organization
        return $user->organization_id === $organizationId;
    }

    /**
     * Check if user can access the specified application
     */
    private function canAccessApplication(User $user, int $applicationId): bool
    {
        $application = Application::find($applicationId);

        if (! $application) {
            return false;
        }

        // Users can only access applications from their organization
        return $application->organization_id === $user->organization_id;
    }

    /**
     * Check if user can manage the specified user
     */
    private function canAccessUser(User $user, int $userId): bool
    {
        // Users can always manage their own profile
        if ($user->id === $userId) {
            return true;
        }

        $targetUser = User::find($userId);

        if (! $targetUser) {
            return false;
        }

        // Organization admins can manage users in their organization
        if ($user->hasRole('organization-admin') || $user->hasRole('Organization Admin') ||
            $user->hasRole('organization-admin', 'api') || $user->hasRole('Organization Admin', 'api')) {
            return $targetUser->organization_id === $user->organization_id;
        }

        // Regular users cannot manage other users
        return false;
    }

    /**
     * Log violation attempts for security monitoring
     */
    private function logViolationAttempt(User $user, string $resourceType, int $resourceId, Request $request): void
    {
        Log::warning('Organization boundary violation attempt', [
            'user_id' => $user->id,
            'user_organization_id' => $user->organization_id,
            'resource_type' => $resourceType,
            'resource_id' => $resourceId,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'route' => $request->route()->getName(),
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'timestamp' => now(),
        ]);

        // Also create an authentication log entry for audit trail
        \App\Models\AuthenticationLog::create([
            'user_id' => $user->id,
            'event' => 'boundary_violation',
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'details' => [
                'resource_type' => $resourceType,
                'resource_id' => $resourceId,
                'route' => $request->route()->getName(),
                'method' => $request->method(),
                'url' => $request->fullUrl(),
            ],
        ]);
    }
}
