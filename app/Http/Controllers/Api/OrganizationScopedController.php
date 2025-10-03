<?php

namespace App\Http\Controllers\Api;

use App\Models\Organization;
use Illuminate\Http\Request;

/**
 * Base controller for organization-scoped resources
 */
abstract class OrganizationScopedController extends BaseApiController
{
    /**
     * Get organization from route parameter or current user's organization
     */
    protected function getOrganization(Request $request): Organization
    {
        // If organization ID/slug is in route parameters
        $organizationId = $request->route('organization') ?? $request->route('organizationId');

        if ($organizationId) {
            $organization = Organization::where('id', $organizationId)
                ->orWhere('slug', $organizationId)
                ->firstOrFail();

            // Validate access
            if (! $this->validateOrganizationAccess($organization->id)) {
                abort(403, 'Access denied to this organization');
            }

            return $organization;
        }

        // Default to current user's organization
        $organization = $this->getCurrentOrganization();

        if (! $organization) {
            abort(400, 'No organization context available');
        }

        return $organization;
    }

    /**
     * Get query builder scoped to organization
     */
    protected function getOrganizationScopedQuery(string $model, Organization $organization): \Illuminate\Database\Eloquent\Builder
    {
        return $model::where('organization_id', $organization->id);
    }

    /**
     * Validate that a resource belongs to the current organization
     */
    protected function validateResourceOrganization(object $resource, Organization $organization): void
    {
        if ($resource->organization_id !== $organization->id && ! $this->isSuperAdmin()) {
            abort(403, 'Resource does not belong to your organization');
        }
    }

    /**
     * Apply organization filters to query
     */
    protected function applyOrganizationFilters(\Illuminate\Database\Eloquent\Builder $query, Organization $organization): \Illuminate\Database\Eloquent\Builder
    {
        if (! $this->isSuperAdmin()) {
            $query->where('organization_id', $organization->id);
        }

        return $query;
    }
}
