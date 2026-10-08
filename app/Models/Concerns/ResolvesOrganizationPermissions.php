<?php

namespace App\Models\Concerns;

use Illuminate\Support\Collection;
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
            && ($this->permissionNamesInTeam($this->organization_id)->contains($permission) || $this->hasCustomPermission($permission))) {
            return true;
        }

        return $this->permissionNamesInTeam(null)->contains($permission);
    }

    /**
     * Permission names the user holds in their organization, globally and through active custom roles of their organization.
     *
     * @return Collection<int, string>
     */
    public function organizationPermissionNames(): Collection
    {
        $names = $this->permissionNamesInTeam(null);

        if ($this->organization_id !== null) {
            $names = $names
                ->merge($this->permissionNamesInTeam($this->organization_id))
                ->merge($this->customRoles()
                    ->where('is_active', true)
                    ->where('custom_roles.organization_id', $this->organization_id)
                    ->get()->pluck('permissions')->flatten());
        }

        return $names->unique()->values();
    }

    /**
     * @return Collection<int, string>
     */
    private function permissionNamesInTeam(?int $teamId): Collection
    {
        $registrar = app(PermissionRegistrar::class);
        $previousTeamId = $registrar->getPermissionsTeamId();
        $relations = $this->getRelations();
        $registrar->setPermissionsTeamId($teamId);
        $this->unsetRelation('roles')->unsetRelation('permissions');

        try {
            return $this->load('permissions')->getAllPermissions()->pluck('name');
        } finally {
            $registrar->setPermissionsTeamId($previousTeamId);
            $this->setRelations($relations);
        }
    }
}
