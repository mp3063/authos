<?php

namespace App\Policies\Concerns;

use App\Models\User;

trait ChecksOrganizationPermissions
{
    protected function permits(User $user, string $permission, ?int $organizationId = null, bool $requireOrganization = true): bool
    {
        if ($user->isSuperAdmin()) {
            return true;
        }

        if ($requireOrganization && ($organizationId === null || $organizationId !== $user->organization_id)) {
            return false;
        }

        return $user->hasOrganizationPermission($permission);
    }
}
