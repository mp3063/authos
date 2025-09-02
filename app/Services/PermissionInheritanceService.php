<?php

namespace App\Services;

use App\Models\User;
use App\Models\Application;
use App\Models\ApplicationGroup;
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
            DB::beginTransaction();

            $user = User::find($userId);
            if (!$user) {
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
                $childApplications = $group->childApplications();
                
                foreach ($childApplications as $childApp) {
                    // Check if user already has access to avoid duplicates
                    if (!$user->applications()->where('application_id', $childApp->id)->exists()) {
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

            DB::commit();
            
            Log::info('Completed cascade application access', [
                'user_id' => $userId,
                'parent_application_id' => $parentApplicationId,
                'cascaded_applications' => $cascadedCount,
            ]);

            return true;

        } catch (\Exception $e) {
            DB::rollBack();
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
            DB::beginTransaction();

            $user = User::find($userId);
            if (!$user) {
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
                $childApplications = $group->childApplications();
                
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

            DB::commit();
            
            Log::info('Completed revoke inherited access', [
                'user_id' => $userId,
                'parent_application_id' => $parentApplicationId,
                'revoked_applications' => $revokedCount,
            ]);

            return true;

        } catch (\Exception $e) {
            DB::rollBack();
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
        if (!$user) {
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
            if (!$user) {
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
            $childIds = $group->child_application_ids ?? [];
            
            // Check if parent appears in children (direct circular reference)
            if (in_array($group->parent_application_id, $childIds)) {
                $issues[] = [
                    'type' => 'circular_dependency',
                    'group_id' => $group->id,
                    'message' => "Group '{$group->name}' has parent application in child list",
                ];
            }

            // Check if child applications exist and belong to organization
            foreach ($childIds as $childId) {
                $childApp = Application::find($childId);
                if (!$childApp || $childApp->organization_id !== $organizationId) {
                    $issues[] = [
                        'type' => 'invalid_child_application',
                        'group_id' => $group->id,
                        'child_application_id' => $childId,
                        'message' => "Child application {$childId} not found or doesn't belong to organization",
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
}