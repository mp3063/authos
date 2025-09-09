<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiResponse;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\Request;

/**
 * Base API controller with common functionality
 */
abstract class BaseApiController extends Controller
{
    use ApiResponse, AuthorizesRequests, ValidatesRequests;

    /**
     * Get the authenticated user
     */
    protected function getAuthenticatedUser()
    {
        return auth()->user();
    }

    /**
     * Get the current organization
     */
    protected function getCurrentOrganization()
    {
        $user = $this->getAuthenticatedUser();

        return $user ? $user->organization : null;
    }

    /**
     * Check if user is super admin
     */
    protected function isSuperAdmin(): bool
    {
        $user = $this->getAuthenticatedUser();

        return $user && $user->isSuperAdmin();
    }

    /**
     * Validate organization access
     */
    protected function validateOrganizationAccess($organizationId): bool
    {
        if ($this->isSuperAdmin()) {
            return true;
        }

        $currentUser = $this->getAuthenticatedUser();

        return $currentUser && $currentUser->organization_id == $organizationId;
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
            parse_str($filters, $filters);
        }

        return $filters;
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
