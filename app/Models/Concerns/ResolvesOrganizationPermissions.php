<?php

namespace App\Models\Concerns;

use Spatie\Permission\PermissionRegistrar;

trait ResolvesOrganizationPermissions
{
    public function hasOrganizationPermission(string $permission): bool
    {
        if ($this->isSuperAdmin()) {
            return true;
        }

        if (app(PermissionRegistrar::class)->getPermissions(['name' => $permission], true)->isEmpty()) {
            return false;
        }

        if ($this->organization_id !== null
            && ($this->holdsPermissionInTeam($permission, $this->organization_id) || $this->hasCustomPermission($permission))) {
            return true;
        }

        return $this->holdsPermissionInTeam($permission, null);
    }

    private function holdsPermissionInTeam(string $permission, ?int $teamId): bool
    {
        $registrar = app(PermissionRegistrar::class);
        $previousTeamId = $registrar->getPermissionsTeamId();
        $registrar->setPermissionsTeamId($teamId);
        $this->unsetRelation('roles')->unsetRelation('permissions');

        try {
            return $this->getAllPermissions()->contains('name', $permission);
        } finally {
            $registrar->setPermissionsTeamId($previousTeamId);
            $this->unsetRelation('roles')->unsetRelation('permissions');
        }
    }
}
