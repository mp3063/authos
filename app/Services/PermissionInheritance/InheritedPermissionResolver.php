<?php

namespace App\Services\PermissionInheritance;

use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\User;

class InheritedPermissionResolver
{
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
            $parentGroup = $this->findInheritableParent($childGroup);

            if ($parentGroup) {
                $allPermissions = array_merge($allPermissions, $this->collectUserPermissions($user, $parentGroup));
            }
        }

        return array_unique($allPermissions);
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
     * Parent group of a child group, when inheritance is enabled for it
     */
    private function findInheritableParent(ApplicationGroup $childGroup): ?ApplicationGroup
    {
        if (! $childGroup->parent_id) {
            return null; // No parent, no inheritance
        }

        // Check if inheritance is enabled in child group settings
        $settings = $childGroup->settings ?? [];
        if (isset($settings['inheritance_enabled']) && ! $settings['inheritance_enabled']) {
            return null;
        }

        return ApplicationGroup::find($childGroup->parent_id);
    }

    /**
     * Permissions the user holds on any application of the given group
     */
    private function collectUserPermissions(User $user, ApplicationGroup $group): array
    {
        $permissions = [];

        foreach ($group->applications as $parentApp) {
            // Check if user has access to this parent application
            $userApp = $user->applications()->where('application_id', $parentApp->id)->first();

            if ($userApp && $userApp->pivot->permissions) {
                $permissions = array_merge($permissions, $userApp->pivot->permissions);
            }
        }

        return $permissions;
    }
}
