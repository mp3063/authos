<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\Organization;

trait FindsOrgScopedOrganizations
{
    protected function findOrganizationWithOrgScope(string|int $id, string $ability = 'view'): Organization
    {
        $caller = auth()->user();
        $query = Organization::query();

        if (! $caller->isSuperAdmin()) {
            $query->whereNotNull('id')->where('id', $caller->organization_id);
        }

        $organization = $query->findOrFail($id);

        $this->authorize($ability, $organization);

        return $organization;
    }
}
