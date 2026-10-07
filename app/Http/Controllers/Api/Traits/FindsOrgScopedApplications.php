<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\Application;

trait FindsOrgScopedApplications
{
    /**
     * Find application with organization scope enforcement
     *
     * This method ensures that non-super-admin users can only access
     * applications within their own organization. This is critical for
     * multi-tenant security and prevents OWASP A01:2021 - Broken Access Control.
     */
    protected function findApplicationWithOrgScope(string $id): Application
    {
        $query = Application::query();

        // Enforce organization-based data isolation for non-super-admin users
        $currentUser = auth()->user();
        if (! $currentUser->hasRole('Super Admin') && ! $currentUser->hasRole('super-admin')) {
            $query->where('organization_id', $currentUser->organization_id);
        }

        return $query->findOrFail($id);
    }
}
