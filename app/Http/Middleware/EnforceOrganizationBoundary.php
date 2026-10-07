<?php

namespace App\Http\Middleware;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class EnforceOrganizationBoundary
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response|RedirectResponse)  $next
     * @return Response|RedirectResponse
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
        if ($this->isSuperAdmin($user)) {
            \Log::info('Super admin detected, allowing access');

            return $next($request);
        }

        \Log::info('Not a super admin, checking organization boundaries');

        [$organizationId, $applicationId, $userId] = $this->resolveRouteResourceIds($request);

        $violation = $this->findBoundaryViolation($user, $organizationId, $applicationId, $userId);

        if ($violation !== null) {
            [$resourceType, $resourceId] = $violation;
            $this->logViolationAttempt($user, $resourceType, $resourceId, $request);

            // Return 404 to not leak information about resource existence
            return response()->json([
                'error' => 'Not found',
                'message' => 'The requested resource was not found.',
            ], 404);
        }

        return $next($request);
    }

    /**
     * @return array{0: mixed, 1: mixed, 2: mixed} organization, application and user IDs from the route
     */
    private function resolveRouteResourceIds(Request $request): array
    {
        $organizationId = $request->route('organizationId');
        $applicationId = $request->route('applicationId');
        $userId = $request->route('userId');

        // For user and application routes, the 'id' parameter refers to those resources, not organization
        $routeUri = $request->route()->uri();

        if (str_contains($routeUri, 'users/{id}')) {
            $userId = $request->route('id');
        } elseif (str_contains($routeUri, 'applications/{id}')) {
            $applicationId = $request->route('id');
        } elseif (str_contains($routeUri, 'organizations/{id}')) {
            $organizationId = $request->route('id');
        }

        return [$organizationId, $applicationId, $userId];
    }

    /**
     * @return array{0: string, 1: mixed}|null the first violated resource type and ID, checked in order
     */
    private function findBoundaryViolation(User $user, mixed $organizationId, mixed $applicationId, mixed $userId): ?array
    {
        if ($organizationId && ! $this->canAccessOrganization($user, $organizationId)) {
            return ['organization', $organizationId];
        }

        if ($applicationId && ! $this->canAccessApplication($user, $applicationId)) {
            return ['application', $applicationId];
        }

        // Validate user access (for user management endpoints)
        if ($userId && ! $this->canAccessUser($user, $userId)) {
            return ['user', $userId];
        }

        return null;
    }

    private function isSuperAdmin(User $user): bool
    {
        return $user->hasRole('super-admin') || $user->hasRole('Super Admin') ||
            $user->hasRole('super-admin', 'api') || $user->hasRole('Super Admin', 'api');
    }

    /**
     * Check if user can access the specified organization
     */
    private function canAccessOrganization(User $user, int $organizationId): bool
    {
        // Super admins can access any organization
        if ($this->isSuperAdmin($user)) {
            return true;
        }

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

        // Super admins can access any application
        if ($this->isSuperAdmin($user)) {
            return true;
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

        // Super admins can access any user
        if ($this->isSuperAdmin($user)) {
            return true;
        }

        // Organization boundary check: users must be in the same organization
        // This enforces data isolation but allows the controller to handle authorization (403)
        // If users are in the same org, let the request through to the controller
        // The controller will check specific permissions and return 403 if needed
        return $targetUser->organization_id === $user->organization_id;
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
        AuthenticationLog::create([
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
