<?php

namespace App\Services\PermissionInheritance;

use App\Models\ApplicationGroup;
use Exception;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class ApplicationGroupHierarchy
{
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

        } catch (Exception $e) {
            Log::error('Failed to bulk update inheritance settings', [
                'group_ids' => $groupIds,
                'settings' => $settings,
                'error' => $e->getMessage(),
            ]);

            return 0;
        }
    }
}
