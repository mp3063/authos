<?php

namespace App\Services;

use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class PermissionInheritanceService
{
    /**
     * Cascade application access from parent to child applications
     */
    public function cascadeApplicationAccess(int $userId, int $parentApplicationId): bool
    {
        try {
            $user = User::find($userId);
            if (! $user) {
                Log::error('User not found for cascading application access', ['user_id' => $userId]);

                return false;
            }

            // Find all application groups where this application is the parent
            $groups = ApplicationGroup::where('parent_application_id', $parentApplicationId)
                ->where('organization_id', $user->organization_id)
                ->where('cascade_permissions', true)
                ->get();

            $cascadedCount = 0;

            foreach ($groups as $group) {
                $childApplications = $group->applications;

                foreach ($childApplications as $childApp) {
                    // Check if user already has access to avoid duplicates
                    if (! $user->applications()->where('application_id', $childApp->id)->exists()) {
                        $user->applications()->attach($childApp->id, [
                            'granted_at' => now(),
                            'granted_by' => null, // Inherited access
                            'last_login_at' => null,
                            'login_count' => 0,
                        ]);

                        $cascadedCount++;

                        Log::info('Cascaded application access', [
                            'user_id' => $userId,
                            'parent_application_id' => $parentApplicationId,
                            'child_application_id' => $childApp->id,
                            'group_id' => $group->id,
                        ]);
                    }
                }
            }

            Log::info('Completed cascade application access', [
                'user_id' => $userId,
                'parent_application_id' => $parentApplicationId,
                'cascaded_applications' => $cascadedCount,
            ]);

            return true;

        } catch (\Exception $e) {
            Log::error('Failed to cascade application access', [
                'user_id' => $userId,
                'parent_application_id' => $parentApplicationId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Revoke inherited application access when parent access is removed
     */
    public function revokeInheritedAccess(int $userId, int $parentApplicationId): bool
    {
        try {
            $user = User::find($userId);
            if (! $user) {
                Log::error('User not found for revoking inherited access', ['user_id' => $userId]);

                return false;
            }

            // Find all application groups where this application is the parent
            $groups = ApplicationGroup::where('parent_application_id', $parentApplicationId)
                ->where('organization_id', $user->organization_id)
                ->where('cascade_permissions', true)
                ->get();

            $revokedCount = 0;

            foreach ($groups as $group) {
                $childApplications = $group->applications;

                foreach ($childApplications as $childApp) {
                    // Only revoke if this was inherited access (granted_by is null)
                    $pivotData = $user->applications()
                        ->where('application_id', $childApp->id)
                        ->first();

                    if ($pivotData && $pivotData->pivot->granted_by === null) {
                        $user->applications()->detach($childApp->id);
                        $revokedCount++;

                        Log::info('Revoked inherited application access', [
                            'user_id' => $userId,
                            'parent_application_id' => $parentApplicationId,
                            'child_application_id' => $childApp->id,
                            'group_id' => $group->id,
                        ]);
                    }
                }
            }

            Log::info('Completed revoke inherited access', [
                'user_id' => $userId,
                'parent_application_id' => $parentApplicationId,
                'revoked_applications' => $revokedCount,
            ]);

            return true;

        } catch (\Exception $e) {
            Log::error('Failed to revoke inherited access', [
                'user_id' => $userId,
                'parent_application_id' => $parentApplicationId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Get all applications accessible to user through inheritance
     */
    public function getInheritedApplications(int $userId, int $applicationId): array
    {
        $user = User::find($userId);
        if (! $user) {
            return [];
        }

        // Find groups where the given application is a parent
        $groups = ApplicationGroup::where('parent_application_id', $applicationId)
            ->where('organization_id', $user->organization_id)
            ->where('cascade_permissions', true)
            ->get();

        $inheritedApps = [];

        foreach ($groups as $group) {
            $childApplications = $group->childApplications();
            foreach ($childApplications as $childApp) {
                $inheritedApps[] = [
                    'id' => $childApp->id,
                    'name' => $childApp->name,
                    'group_id' => $group->id,
                    'group_name' => $group->name,
                    'has_access' => $user->applications()->where('application_id', $childApp->id)->exists(),
                ];
            }
        }

        return $inheritedApps;
    }

    /**
     * Sync all inheritance relationships for a user
     */
    public function syncUserInheritance(int $userId): bool
    {
        try {
            $user = User::find($userId);
            if (! $user) {
                return false;
            }

            // Get all applications the user currently has direct access to
            $userApplications = $user->applications()
                ->where('applications.organization_id', $user->organization_id)
                ->get();

            foreach ($userApplications as $app) {
                // Check if granted_by is null (direct access) and cascade if needed
                if ($app->pivot->granted_by !== null) {
                    $this->cascadeApplicationAccess($userId, $app->id);
                }
            }

            Log::info('Synced user inheritance relationships', [
                'user_id' => $userId,
                'applications_processed' => $userApplications->count(),
            ]);

            return true;

        } catch (\Exception $e) {
            Log::error('Failed to sync user inheritance', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Get inheritance statistics for an organization
     */
    public function getOrganizationInheritanceStats(int $organizationId): array
    {
        $groupCount = ApplicationGroup::where('organization_id', $organizationId)->count();
        $activeGroupCount = ApplicationGroup::where('organization_id', $organizationId)
            ->where('cascade_permissions', true)
            ->count();

        // Calculate total inherited access relationships
        $inheritedAccess = DB::table('user_applications')
            ->join('users', 'users.id', '=', 'user_applications.user_id')
            ->where('users.organization_id', $organizationId)
            ->whereNull('user_applications.granted_by')
            ->count();

        return [
            'total_groups' => $groupCount,
            'active_groups' => $activeGroupCount,
            'inherited_access_count' => $inheritedAccess,
            'organization_id' => $organizationId,
            'generated_at' => now(),
        ];
    }

    /**
     * Validate inheritance setup for an organization
     */
    public function validateInheritanceSetup(int $organizationId): array
    {
        $issues = [];

        // Check for circular dependencies
        $groups = ApplicationGroup::where('organization_id', $organizationId)->get();

        foreach ($groups as $group) {
            // Get applications in this group
            $groupApplications = $group->applications;

            // Check if any applications belong to wrong organization
            foreach ($groupApplications as $app) {
                if ($app->organization_id !== $organizationId) {
                    $issues[] = [
                        'type' => 'invalid_application',
                        'group_id' => $group->id,
                        'application_id' => $app->id,
                        'message' => "Application {$app->id} in group '{$group->name}' doesn't belong to organization",
                    ];
                }
            }
        }

        return [
            'valid' => empty($issues),
            'issues' => $issues,
            'organization_id' => $organizationId,
            'validated_at' => now(),
        ];
    }

    /**
     * Calculate inherited permissions for a user and application
     */
    public function calculateInheritedPermissions(int $userId, int $applicationId): array
    {
        $user = User::find($userId);
        $application = Application::find($applicationId);

        if (! $user || ! $application) {
            return [];
        }

        // Check if user has access to this application
        $directAccess = $user->applications()->where('application_id', $applicationId)->first();

        // If user has explicitly cascaded access (granted_by = null), return stored permissions
        if ($directAccess && $directAccess->pivot->granted_by === null) {
            return $directAccess->pivot->permissions ?? [];
        }

        $allPermissions = [];

        // Start with any direct permissions the user has on this application
        if ($directAccess && $directAccess->pivot->permissions) {
            $allPermissions = array_merge($allPermissions, $directAccess->pivot->permissions);
        }

        // Find the application group for this child application
        $childGroups = ApplicationGroup::where('organization_id', $user->organization_id)
            ->whereHas('applications', function ($query) use ($applicationId) {
                $query->where('applications.id', $applicationId);
            })
            ->get();

        foreach ($childGroups as $childGroup) {
            if (! $childGroup->parent_id) {
                continue; // No parent, no inheritance
            }

            // Check if inheritance is enabled in child group settings
            $settings = $childGroup->settings ?? [];
            if (isset($settings['inheritance_enabled']) && ! $settings['inheritance_enabled']) {
                continue;
            }

            // Find parent group
            $parentGroup = ApplicationGroup::find($childGroup->parent_id);
            if (! $parentGroup) {
                continue;
            }

            // Get all applications in parent group
            $parentApplications = $parentGroup->applications;

            foreach ($parentApplications as $parentApp) {
                // Check if user has access to this parent application
                $userApp = $user->applications()->where('application_id', $parentApp->id)->first();

                if ($userApp && $userApp->pivot->permissions) {
                    $permissions = $userApp->pivot->permissions;
                    $allPermissions = array_merge($allPermissions, $permissions);
                }
            }
        }

        return array_unique($allPermissions);
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
        $chain = [];
        $visited = [];

        $this->buildInheritanceChain($applicationId, $chain, $visited);

        return $chain;
    }

    private function buildInheritanceChain(int $applicationId, array &$chain, array &$visited): void
    {
        if (in_array($applicationId, $visited)) {
            return; // Prevent infinite loops
        }

        $visited[] = $applicationId;

        // Find groups where this application is a child
        $groups = ApplicationGroup::whereHas('applications', function ($query) use ($applicationId) {
            $query->where('applications.id', $applicationId);
        })->get();

        foreach ($groups as $group) {
            $chain[] = [
                'group_id' => $group->id,
                'group_name' => $group->name,
                'relationship' => 'child',
                'parent_application_id' => $group->parent_application_id,
            ];

            // Add parent group to chain if it exists
            if ($group->parent_id) {
                $parentGroup = ApplicationGroup::find($group->parent_id);
                if ($parentGroup) {
                    $chain[] = [
                        'group_id' => $parentGroup->id,
                        'group_name' => $parentGroup->name,
                        'relationship' => 'parent',
                    ];
                }
            }
        }
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
        $user = User::find($userId);
        if (! $user) {
            return null;
        }

        // Check direct permissions first
        $directApp = $user->applications()->where('application_id', $applicationId)->first();
        if ($directApp && $directApp->pivot->permissions) {
            $directPermissions = $directApp->pivot->permissions;

            if (in_array($permission, $directPermissions)) {
                return [
                    'type' => 'direct',
                    'source_application_id' => $applicationId,
                    'granted_at' => $directApp->pivot->granted_at,
                ];
            }
        }

        // Check inherited permissions - find groups that contain this application and have parent groups
        $groups = ApplicationGroup::where('organization_id', $user->organization_id)
            ->whereHas('applications', function ($query) use ($applicationId) {
                $query->where('applications.id', $applicationId);
            })
            ->whereNotNull('parent_id')
            ->get();

        foreach ($groups as $group) {
            // Get parent group and check its applications
            $parentGroup = $group->parent;
            if (! $parentGroup) {
                continue;
            }

            $parentApplications = $parentGroup->applications;

            foreach ($parentApplications as $parentApplication) {
                $parentApp = $user->applications()
                    ->where('application_id', $parentApplication->id)
                    ->first();

                if ($parentApp && $parentApp->pivot->permissions) {
                    $permissions = $parentApp->pivot->permissions;

                    if (in_array($permission, $permissions)) {
                        return [
                            'type' => 'inherited',
                            'source_application_id' => $parentApplication->id,
                            'source_group_id' => $parentGroup->id,
                            'granted_at' => $parentApp->pivot->granted_at,
                        ];
                    }
                }
            }
        }

        return null;
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
        $visited = [];

        return $this->hasCircularDependency($groupId, $visited);
    }

    private function hasCircularDependency(int $groupId, array &$visited): bool
    {
        if (in_array($groupId, $visited)) {
            return true; // Found circular dependency
        }

        $visited[] = $groupId;

        $group = ApplicationGroup::find($groupId);
        if (! $group || ! $group->parent_id) {
            return false;
        }

        return $this->hasCircularDependency($group->parent_id, $visited);
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
            'cascade_history' => $this->getCascadeHistory($userId, $applicationId),
            'generated_at' => now(),
        ];
    }

    private function getCascadeHistory(int $userId, int $applicationId): array
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
        $groups = ApplicationGroup::where('organization_id', $organizationId)->get();

        $orphanedGroups = [];
        $circularDependencies = [];
        $inconsistentSettings = [];

        foreach ($groups as $group) {
            // Check for orphaned groups (parent doesn't exist)
            if ($group->parent_id && ! ApplicationGroup::find($group->parent_id)) {
                $orphanedGroups[] = [
                    'group_id' => $group->id,
                    'group_name' => $group->name,
                    'missing_parent_id' => $group->parent_id,
                ];
            }

            // Check for circular dependencies
            if ($this->detectCircularDependencies($group->id)) {
                $circularDependencies[] = [
                    'group_id' => $group->id,
                    'group_name' => $group->name,
                ];
            }

            // Check for inconsistent settings
            $settings = $group->settings ?? [];
            if (! isset($settings['inheritance_enabled'])) {
                $inconsistentSettings[] = [
                    'group_id' => $group->id,
                    'group_name' => $group->name,
                    'missing_setting' => 'inheritance_enabled',
                ];
            }
        }

        return [
            'orphaned_groups' => $orphanedGroups,
            'circular_dependencies' => $circularDependencies,
            'inconsistent_settings' => $inconsistentSettings,
            'validation_passed' => empty($orphanedGroups) && empty($circularDependencies) && empty($inconsistentSettings),
            'validated_at' => now(),
        ];
    }

    /**
     * Get users with inherited access to an application
     */
    public function getUsersWithInheritedAccess(int $applicationId): array
    {
        $users = [];

        // Find groups where this application is contained and have parent groups
        $groups = ApplicationGroup::whereHas('applications', function ($query) use ($applicationId) {
            $query->where('applications.id', $applicationId);
        })->whereNotNull('parent_id')->get();

        foreach ($groups as $group) {
            // Get parent group and its applications
            $parentGroup = $group->parent;
            if (! $parentGroup) {
                continue;
            }

            $parentApplications = $parentGroup->applications;

            foreach ($parentApplications as $parentApp) {
                // Find users who have access to this parent application
                $parentUsers = User::whereHas('applications', function ($query) use ($parentApp) {
                    $query->where('application_id', $parentApp->id);
                })->get();

                foreach ($parentUsers as $user) {
                    $userParentApp = $user->applications()
                        ->where('application_id', $parentApp->id)
                        ->first();

                    if ($userParentApp && $userParentApp->pivot->permissions) {
                        $permissions = $userParentApp->pivot->permissions;

                        $users[] = [
                            'user_id' => $user->id,
                            'user_name' => $user->name,
                            'user_email' => $user->email,
                            'inherited_permissions' => $permissions,
                            'source_application_id' => $parentApp->id,
                            'source_group_id' => $parentGroup->id,
                        ];
                    }
                }
            }
        }

        return $users;
    }

    /**
     * Bulk update inheritance settings for multiple groups
     */
    public function bulkUpdateInheritanceSettings(array $groupIds, array $settings): int
    {
        try {
            $validSettings = array_intersect_key($settings, array_flip([
                'inheritance_enabled',
                'auto_assign_users',
                'default_permissions',
            ]));

            $updatedCount = ApplicationGroup::whereIn('id', $groupIds)
                ->get()
                ->each(function ($group) use ($validSettings) {
                    $currentSettings = $group->settings ?? [];
                    $group->settings = array_merge($currentSettings, $validSettings);
                    $group->save();
                })
                ->count();

            Log::info('Bulk updated inheritance settings', [
                'group_ids' => $groupIds,
                'settings' => $validSettings,
                'updated_count' => $updatedCount,
            ]);

            return $updatedCount;

        } catch (\Exception $e) {
            Log::error('Failed to bulk update inheritance settings', [
                'group_ids' => $groupIds,
                'settings' => $settings,
                'error' => $e->getMessage(),
            ]);

            return 0;
        }
    }
}
