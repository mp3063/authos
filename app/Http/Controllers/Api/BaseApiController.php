<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiResponse;
use App\Http\Controllers\Controller;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\Request;

/**
 * Base API controller with common functionality
 */
abstract class BaseApiController extends Controller
{
    use ApiResponse;
    use AuthorizesRequests;
    use ValidatesRequests;

    /**
     * Get the authenticated user
     */
    protected function getAuthenticatedUser(): ?User
    {
        /** @var \App\Models\User|null $user */
        $user = auth('api')->user();

        // Set team context for Spatie Permission
        if ($user && $user->organization_id && method_exists($user, 'setPermissionsTeamId')) {
            // Clear cached permissions before setting new team context
            app(\Spatie\Permission\PermissionRegistrar::class)->forgetCachedPermissions();

            // Refresh user from database to ensure we have fresh role/permission relationships
            // This is important for tests and ensures permission checks work correctly
            $user = User::with('roles', 'permissions')->find($user->id);

            if ($user) {
                $user->setPermissionsTeamId($user->organization_id);
                app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);
            }
        }

        return $user;
    }

    /**
     * Get the current organization
     */
    protected function getCurrentOrganization(): ?Organization
    {
        $user = $this->getAuthenticatedUser();

        return $user?->organization;
    }

    /**
     * Check if user is super admin
     */
    protected function isSuperAdmin(): bool
    {
        $user = $this->getAuthenticatedUser();

        return $user?->isSuperAdmin() ?? false;
    }

    /**
     * Validate organization access
     */
    protected function validateOrganizationAccess(int|string $organizationId): bool
    {
        if ($this->isSuperAdmin()) {
            return true;
        }

        $currentUser = $this->getAuthenticatedUser();

        return $currentUser?->organization_id == $organizationId;
    }

    /**
     * Get pagination parameters from request
     */
    protected function getPaginationParams(Request $request): array
    {
        return [
            'page' => $request->get('page', 1),
            'per_page' => min($request->get('per_page', 15), 100), // Max 100 items per page
            'sort' => $request->get('sort', 'id'),
            'order' => $request->get('order', 'asc'),
        ];
    }

    /**
     * Get filter parameters from request
     */
    protected function getFilterParams(Request $request): array
    {
        $filters = $request->get('filter', []);

        if (is_string($filters)) {
            $parsedFilters = [];
            parse_str($filters, $parsedFilters);
            $filters = $parsedFilters;
        }

        return is_array($filters) ? $filters : [];
    }

    /**
     * Get search parameters from request
     */
    protected function getSearchParams(Request $request): array
    {
        return [
            'search' => $request->get('search'),
            'search_fields' => $request->get('search_fields', []),
        ];
    }

    /**
     * Log API action
     */
    protected function logApiAction(string $action, array $context = []): void
    {
        activity()
            ->causedBy($this->getAuthenticatedUser())
            ->withProperties($context)
            ->log($action);
    }
}
