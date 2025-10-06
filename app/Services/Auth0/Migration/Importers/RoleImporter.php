<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration\Importers;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Services\Auth0\DTOs\Auth0RoleDTO;
use App\Services\Auth0\Migration\ImportResult;
use Illuminate\Support\Facades\DB;
use Spatie\Permission\Models\Permission;

class RoleImporter
{
    public function __construct(
        private ?Organization $defaultOrganization = null,
    ) {}

    /**
     * Import roles from Auth0
     *
     * @param  array<int, Auth0RoleDTO>  $auth0Roles
     */
    public function import(array $auth0Roles, bool $dryRun = false): ImportResult
    {
        $result = new ImportResult;

        foreach ($auth0Roles as $auth0Role) {
            try {
                // Skip system roles (they already exist in our system)
                if ($auth0Role->isSystemRole()) {
                    $result->addSkipped("Skipping system role: {$auth0Role->name}");

                    continue;
                }

                // Check if role already exists
                if ($this->roleExists($auth0Role->name)) {
                    $result->addSkipped("Role with name {$auth0Role->name} already exists");

                    continue;
                }

                if ($dryRun) {
                    $result->addSuccess($auth0Role, null);

                    continue;
                }

                // Import role
                $role = $this->importRole($auth0Role);

                $result->addSuccess($auth0Role, $role->id);
            } catch (\Throwable $e) {
                $result->addFailure($auth0Role, $e);
            }
        }

        return $result;
    }

    /**
     * Import a single role
     */
    private function importRole(Auth0RoleDTO $auth0Role): CustomRole
    {
        return DB::transaction(function () use ($auth0Role) {
            // Create custom role
            $role = CustomRole::create([
                'name' => $auth0Role->name,
                'description' => $auth0Role->description,
                'organization_id' => $this->getOrganizationId(),
            ]);

            // Store Auth0 metadata
            $role->update([
                'metadata' => [
                    'auth0_role_id' => $auth0Role->id,
                    'imported_from_auth0' => true,
                    'imported_at' => now()->toIso8601String(),
                ],
            ]);

            // Import permissions
            $this->importPermissions($role, $auth0Role);

            return $role;
        });
    }

    /**
     * Import role permissions
     */
    private function importPermissions(CustomRole $role, Auth0RoleDTO $auth0Role): void
    {
        $permissions = [];

        foreach ($auth0Role->getPermissionNames() as $permissionName) {
            // Map Auth0 permission to our permission
            $mappedPermission = $this->mapPermission($permissionName);

            if (! $mappedPermission) {
                continue;
            }

            // Find or create permission
            $permission = Permission::firstOrCreate([
                'name' => $mappedPermission,
                'guard_name' => 'web',
            ]);

            $permissions[] = $permission->id;
        }

        // Sync permissions to role
        if (! empty($permissions)) {
            $role->permissions()->sync($permissions);
        }
    }

    /**
     * Map Auth0 permission to our permission system
     */
    private function mapPermission(string $auth0Permission): ?string
    {
        // Auth0 permissions are typically in format: resource:action
        // e.g., "users:read", "users:write", "applications:manage"

        // Extract action and resource
        if (! str_contains($auth0Permission, ':')) {
            return null;
        }

        [$resource, $action] = explode(':', $auth0Permission, 2);

        // Map to our permission naming convention
        return match ($action) {
            'read' => "view_{$resource}",
            'write', 'create' => "create_{$resource}",
            'update' => "update_{$resource}",
            'delete' => "delete_{$resource}",
            'manage' => "manage_{$resource}",
            default => null,
        };
    }

    /**
     * Check if role exists
     */
    private function roleExists(string $name): bool
    {
        // Check custom roles
        if (CustomRole::where('name', $name)->exists()) {
            return true;
        }

        // Check Spatie roles
        if (config('permission.models.role')::where('name', $name)->exists()) {
            return true;
        }

        return false;
    }

    /**
     * Get organization ID for imported roles
     */
    private function getOrganizationId(): ?int
    {
        return $this->defaultOrganization?->id;
    }

    /**
     * Set default organization for imported roles
     */
    public function setDefaultOrganization(Organization $organization): void
    {
        $this->defaultOrganization = $organization;
    }
}
