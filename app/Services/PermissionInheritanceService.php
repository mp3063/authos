<?php

namespace App\Services;

use App\Models\ApplicationGroup;
use App\Models\User;
use App\Services\PermissionInheritance\ApplicationGroupHierarchy;
use App\Services\PermissionInheritance\InheritedPermissionResolver;

class PermissionInheritanceService
{
    public function __construct(
        protected ApplicationGroupHierarchy $groupHierarchy,
        protected InheritedPermissionResolver $permissionResolver,
    ) {}

    /**
     * Get inheritance statistics for an organization
     */
    public function getOrganizationInheritanceStats(int $organizationId): array
    {
        return $this->groupHierarchy->getOrganizationInheritanceStats($organizationId);
    }

    /**
     * Validate inheritance setup for an organization
     */
    public function validateInheritanceSetup(int $organizationId): array
    {
        return $this->groupHierarchy->validateInheritanceSetup($organizationId);
    }

    /**
     * Calculate inherited permissions for a user and application
     */
    public function calculateInheritedPermissions(int $userId, int $applicationId): array
    {
        return $this->permissionResolver->calculateInheritedPermissions($userId, $applicationId);
    }

    /**
     * Cascade permissions to children applications
     */
    public function cascadePermissionsToChildren(int $userId, int $parentApplicationId): int
    {
        $user = User::find($userId);
        if (! $user) {
            return 0;
        }

        // Get user's permissions for parent application
        $parentApp = $user->applications()->where('application_id', $parentApplicationId)->first();
        if (! $parentApp || ! $parentApp->pivot->permissions) {
            return 0;
        }

        $permissions = $parentApp->pivot->permissions;
        $cascadedCount = 0;

        // Find parent application groups that contain this application
        $parentGroups = ApplicationGroup::where('organization_id', $user->organization_id)
            ->whereHas('applications', function ($query) use ($parentApplicationId) {
                $query->where('applications.id', $parentApplicationId);
            })
            ->get();

        foreach ($parentGroups as $parentGroup) {
            // Find child groups recursively
            $allChildGroups = $this->getAllDescendantGroups($parentGroup);

            foreach ($allChildGroups as $childGroup) {
                // Check if cascade is enabled (default to true if not explicitly set to false)
                $settings = $childGroup->settings ?? [];
                if (isset($settings['inheritance_enabled']) && $settings['inheritance_enabled'] === false) {
                    continue;
                }

                // Get all applications in child group
                $childApplications = $childGroup->applications;

                foreach ($childApplications as $childApp) {
                    // Skip if user already has access
                    if ($user->applications()->where('application_id', $childApp->id)->exists()) {
                        continue;
                    }

                    $user->applications()->attach($childApp->id, [
                        'permissions' => $permissions,
                        'granted_at' => now(),
                        'granted_by' => null, // Indicates inherited access
                    ]);

                    $cascadedCount++;
                }
            }
        }

        return $cascadedCount;
    }

    /**
     * Get all descendant groups recursively
     */
    private function getAllDescendantGroups(ApplicationGroup $parentGroup): array
    {
        $allDescendants = [];

        // Get direct children
        $children = $parentGroup->children()->get();

        foreach ($children as $child) {
            $allDescendants[] = $child;
            // Recursively get grandchildren and beyond
            $allDescendants = array_merge($allDescendants, $this->getAllDescendantGroups($child));
        }

        return $allDescendants;
    }

    /**
     * Get permission inheritance chain for an application
     */
    public function getPermissionInheritanceChain(int $applicationId): array
    {
        return $this->groupHierarchy->getPermissionInheritanceChain($applicationId);
    }

    /**
     * Get effective permissions combining all sources
     */
    public function getEffectivePermissions(int $userId, int $applicationId): array
    {
        return $this->calculateInheritedPermissions($userId, $applicationId);
    }

    /**
     * Get permission source information
     */
    public function getPermissionSource(int $userId, int $applicationId, string $permission): ?array
    {
        return $this->permissionResolver->getPermissionSource($userId, $applicationId, $permission);
    }

    /**
     * Revoke cascaded permissions
     */
    public function revokeCascadedPermissions(int $userId, int $parentApplicationId, array $permissions): int
    {
        $user = User::find($userId);
        if (! $user) {
            return 0;
        }

        // Find parent application groups that contain this application
        $groups = ApplicationGroup::where('organization_id', $user->organization_id)
            ->whereHas('applications', function ($query) use ($parentApplicationId) {
                $query->where('applications.id', $parentApplicationId);
            })
            ->get();

        $revokedCount = 0;

        foreach ($groups as $group) {
            // Get all descendant groups and their applications
            $descendantGroups = $this->getAllDescendantGroups($group);

            foreach ($descendantGroups as $descendantGroup) {
                $descendantApplications = $descendantGroup->applications;

                foreach ($descendantApplications as $descendantApp) {
                    $childApp = $user->applications()->where('application_id', $descendantApp->id)->first();
                    if (! $childApp || $childApp->pivot->granted_by !== null) {
                        continue; // Skip if not inherited access
                    }

                    $currentPermissions = $childApp->pivot->permissions ?? [];
                    $newPermissions = array_diff($currentPermissions, $permissions);

                    if (empty($newPermissions)) {
                        // Remove access entirely if no permissions remain
                        $user->applications()->detach($descendantApp->id);
                    } else {
                        // Update with remaining permissions
                        $user->applications()->updateExistingPivot($descendantApp->id, [
                            'permissions' => array_values($newPermissions),
                        ]);
                    }

                    $revokedCount++;
                }
            }
        }

        return $revokedCount;
    }

    /**
     * Detect circular dependencies in group hierarchy
     */
    public function detectCircularDependencies(int $groupId): bool
    {
        return $this->groupHierarchy->detectCircularDependencies($groupId);
    }

    /**
     * Get permission audit trail
     */
    public function getPermissionAuditTrail(int $userId, int $applicationId): array
    {
        $inheritedPermissions = $this->calculateInheritedPermissions($userId, $applicationId);
        $inheritanceChain = $this->getPermissionInheritanceChain($applicationId);

        return [
            'user_id' => $userId,
            'application_id' => $applicationId,
            'inherited_permissions' => $inheritedPermissions,
            'inheritance_chain' => $inheritanceChain,
            'cascade_history' => $this->getCascadeHistory(),
            'generated_at' => now(),
        ];
    }

    private function getCascadeHistory(): array
    {
        // This would typically involve checking logs or historical data
        // For now, return basic information
        return [
            'last_cascade' => now(),
            'cascade_count' => 0,
        ];
    }

    /**
     * Validate inheritance hierarchy
     */
    public function validateInheritanceHierarchy(int $organizationId): array
    {
        return $this->groupHierarchy->validateInheritanceHierarchy($organizationId);
    }

    /**
     * Get users with inherited access to an application
     */
    public function getUsersWithInheritedAccess(int $applicationId): array
    {
        return $this->permissionResolver->getUsersWithInheritedAccess($applicationId);
    }

    /**
     * Bulk update inheritance settings for multiple groups
     */
    public function bulkUpdateInheritanceSettings(array $groupIds, array $settings): int
    {
        return $this->groupHierarchy->bulkUpdateInheritanceSettings($groupIds, $settings);
    }
}
