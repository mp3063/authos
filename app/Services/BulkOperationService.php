<?php

namespace App\Services;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use App\Services\Contracts\BulkOperationServiceInterface;
use Exception;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Spatie\Activitylog\Models\Activity;

class BulkOperationService extends BaseService implements BulkOperationServiceInterface
{
    public function __construct(protected BulkInvitationService $bulkInvitationService) {}

    /**
     * Bulk invite multiple users to an organization
     */
    public function bulkInviteUsers(array $invitations, Organization $organization, string $roleId): array
    {
        return $this->bulkInvitationService->inviteUsers($invitations, $organization, $roleId);
    }

    /**
     * Bulk assign roles to multiple users
     */
    public function bulkAssignRoles(array $userIds, string $roleId, Organization $organization): array
    {
        return $this->bulkAssignOrRevokeRoles($userIds, [$roleId], [], 'assign', $organization, auth()->user() ?? User::first());
    }

    /**
     * Bulk assign or revoke roles for multiple users (extended method)
     */
    public function bulkAssignOrRevokeRoles(
        array $userIds,
        array $roles,
        array $customRoleIds,
        string $action,
        Organization $organization,
        User $currentUser
    ): array {
        $users = User::whereIn('id', $userIds)->get();

        // Validate that all users belong to the organization
        $invalidUsers = $users->where('organization_id', '!=', $organization->id);
        if ($invalidUsers->count() > 0) {
            throw new InvalidArgumentException('One or more users do not belong to this organization.');
        }

        // Validate that custom roles belong to the organization
        if (! empty($customRoleIds)) {
            $customRoles = CustomRole::whereIn('id', $customRoleIds)
                ->where('organization_id', $organization->id)
                ->active()
                ->get();

            if ($customRoles->count() !== count($customRoleIds)) {
                throw new InvalidArgumentException('One or more custom roles do not belong to this organization.');
            }
        }

        $results = [
            'successful' => [],
            'failed' => [],
        ];

        return DB::transaction(function () use ($users, $roles, $customRoleIds, $action, $organization, $currentUser, &$results) {
            foreach ($users as $user) {
                try {
                    if ($action === 'assign') {
                        $this->assignRolesToUser($user, $roles, $customRoleIds, $organization, $currentUser);
                    } else {
                        $this->revokeRolesFromUser($user, $roles, $customRoleIds, $organization);
                    }

                    $results['successful'][] = $this->formatUserResult($user);
                } catch (Exception $e) {
                    $results['failed'][] = $this->formatErrorResult($user, $e->getMessage());
                }
            }

            return $results;
        });
    }

    /**
     * Bulk revoke access for multiple users
     */
    public function bulkRevokeAccess(array $userIds, int $applicationId, Organization $organization): array
    {
        return $this->bulkRevokeAccessExtended($userIds, ['application_ids' => [$applicationId]], $organization, auth()->user() ?? User::first());
    }

    /**
     * Bulk revoke access for multiple users (extended method)
     */
    public function bulkRevokeAccessExtended(
        array $userIds,
        array $options,
        Organization $organization,
        User $currentUser
    ): array {
        $users = User::whereIn('id', $userIds)->get();
        $applicationIds = $options['application_ids'] ?? [];
        $revokeTokens = $options['revoke_tokens'] ?? true;
        $revokeAllAccess = $options['revoke_all_access'] ?? false;

        $results = [
            'successful' => [],
            'failed' => [],
        ];

        return DB::transaction(function () use ($users, $organization, $applicationIds, $revokeTokens, $revokeAllAccess, $currentUser, &$results, $options) {
            foreach ($users as $user) {
                try {
                    if ($revokeAllAccess) {
                        $this->revokeAllUserAccess($user, $organization, $revokeTokens);
                    } else {
                        $this->revokeSpecificUserAccess($user, $organization, $applicationIds, $revokeTokens);
                    }

                    $results['successful'][] = $this->formatUserResult($user);
                } catch (Exception $e) {
                    $results['failed'][] = $this->formatErrorResult($user, $e->getMessage());
                }
            }

            // Log bulk revocation activity
            $this->logBulkRevocationActivity($organization, $currentUser, $results, $applicationIds, $revokeAllAccess, $revokeTokens, $options['reason'] ?? null);

            return $results;
        });
    }

    /**
     * Check if the user has permission to manage the organization
     */
    public function checkOrganizationPermission(User $user, Organization $organization): bool
    {
        return $user->isSuperAdmin() || $user->organization_id === $organization->id;
    }

    /**
     * Format user result for bulk operations
     */
    private function formatUserResult(User $user, ?string $operation = null): array
    {
        $result = [
            'user_id' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
        ];

        if ($operation) {
            $result['operation'] = $operation;
        }

        return $result;
    }

    /**
     * Format error result for bulk operations
     */
    private function formatErrorResult(User $user, string $reason): array
    {
        return [
            'user_id' => $user->id,
            'email' => $user->email,
            'reason' => $reason,
        ];
    }

    /**
     * Assign roles to a user
     */
    private function assignRolesToUser(User $user, array $roles, array $customRoleIds, Organization $organization, User $currentUser): void
    {
        // Assign standard roles
        foreach ($roles as $role) {
            if (! $user->hasOrganizationRole($role, $organization->id)) {
                $user->assignOrganizationRole($role, $organization->id);
            }
        }

        // Assign custom roles
        foreach ($customRoleIds as $customRoleId) {
            $user->customRoles()->syncWithoutDetaching([
                $customRoleId => [
                    'granted_at' => now(),
                    'granted_by' => $currentUser->id,
                ],
            ]);
        }
    }

    /**
     * Revoke roles from a user
     */
    private function revokeRolesFromUser(User $user, array $roles, array $customRoleIds, Organization $organization): void
    {
        // Revoke standard roles
        foreach ($roles as $role) {
            if ($user->hasOrganizationRole($role, $organization->id)) {
                $user->removeOrganizationRole($role, $organization->id);
            }
        }

        // Revoke custom roles
        $user->customRoles()->detach($customRoleIds);
    }

    /**
     * Revoke all access for a user in an organization
     */
    private function revokeAllUserAccess(User $user, Organization $organization, bool $revokeTokens): void
    {
        // Remove all application access for this organization
        $orgApplications = $organization->applications()->pluck('id');
        $user->applications()->detach($orgApplications);

        // Remove all custom roles for this organization
        $customRoles = CustomRole::where('organization_id', $organization->id)->pluck('id');
        $user->customRoles()->detach($customRoles);

        // Remove standard roles for this organization
        $user->roles()->wherePivot('organization_id', $organization->id)->detach();

        if ($revokeTokens) {
            // Revoke all tokens for organization applications
            $user->tokens()->whereHas('client', function ($query) use ($orgApplications) {
                $query->whereIn('id', $orgApplications);
            })->delete();
        }
    }

    /**
     * Revoke specific application access for a user
     */
    private function revokeSpecificUserAccess(User $user, Organization $organization, array $applicationIds, bool $revokeTokens): void
    {
        if (! empty($applicationIds)) {
            // Validate applications belong to organization
            $validApplications = $organization->applications()->whereIn('id', $applicationIds)->pluck('id');
            $user->applications()->detach($validApplications);

            if ($revokeTokens) {
                $user->tokens()->whereHas('client', function ($query) use ($validApplications) {
                    $query->whereIn('id', $validApplications);
                })->delete();
            }
        }
    }

    /**
     * Log bulk revocation activity
     */
    private function logBulkRevocationActivity(
        Organization $organization,
        User $currentUser,
        array $results,
        array $applicationIds,
        bool $revokeAllAccess,
        bool $revokeTokens,
        ?string $reason
    ): void {
        Activity::create([
            'log_name' => 'default',
            'description' => 'Bulk application access revocation',
            'subject_type' => Organization::class,
            'subject_id' => $organization->id,
            'causer_type' => User::class,
            'causer_id' => $currentUser->id,
            'properties' => [
                'user_count' => count($results['successful']),
                'application_ids' => $applicationIds,
                'revoke_all_access' => $revokeAllAccess,
                'revoke_tokens' => $revokeTokens,
                'reason' => $reason,
            ],
        ]);
    }

    public function bulkRevokeRoles(array $userIds, string $roleId, Organization $organization): array
    {
        return $this->bulkAssignOrRevokeRoles($userIds, [$roleId], [], 'revoke', $organization, auth()->user() ?? User::first());
    }

    public function bulkUserOperations(array $userIds, string $operation, Organization $organization): array
    {
        $results = [
            'successful' => [],
            'failed' => [],
        ];

        $users = User::whereIn('id', $userIds)
            ->where('organization_id', $organization->id)
            ->get();

        return DB::transaction(function () use ($users, $operation, &$results) {
            foreach ($users as $user) {
                try {
                    switch ($operation) {
                        case 'activate':
                            $user->update(['is_active' => true]);
                            break;
                        case 'deactivate':
                            $user->update(['is_active' => false]);
                            break;
                        case 'delete':
                            $user->delete();
                            break;
                        default:
                            throw new InvalidArgumentException("Invalid operation: $operation");
                    }

                    $results['successful'][] = $this->formatUserResult($user, $operation);
                } catch (Exception $e) {
                    $results['failed'][] = $this->formatErrorResult($user, $e->getMessage());
                }
            }

            return $results;
        });
    }
}
