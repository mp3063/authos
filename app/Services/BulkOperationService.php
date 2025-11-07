<?php

namespace App\Services;

use App\Exports\UsersExport;
use App\Imports\UsersImport;
use App\Mail\OrganizationInvitation;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Services\Contracts\BulkOperationServiceInterface;
use Carbon\Carbon;
use Exception;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use InvalidArgumentException;
use League\Csv\Writer;
use Maatwebsite\Excel\Facades\Excel;
use Spatie\Activitylog\Models\Activity;
use SplTempFileObject;

class BulkOperationService extends BaseService implements BulkOperationServiceInterface
{
    protected InvitationService $invitationService;

    public function __construct(InvitationService $invitationService)
    {
        $this->invitationService = $invitationService;
    }

    /**
     * Bulk invite multiple users to an organization
     */
    public function bulkInviteUsers(array $invitations, Organization $organization, string $roleId): array
    {
        $results = [
            'successful' => [],
            'failed' => [],
            'already_exists' => [],
        ];

        // Create a mock inviter for interface compatibility
        $inviter = auth()->user() ?? User::first();

        return DB::transaction(function () use ($organization, $invitations, $inviter, $roleId, &$results) {
            foreach ($invitations as $invitationData) {
                try {
                    // Ensure invitationData is properly formatted
                    if (is_string($invitationData)) {
                        $invitationData = ['email' => $invitationData, 'role' => $roleId];
                    } else {
                        $invitationData['role'] = $invitationData['role'] ?? $roleId;
                    }

                    // Validate invitation requirements
                    $validationResult = $this->validateInvitationData($invitationData, $organization);
                    if ($validationResult) {
                        $results[$validationResult['type']][] = $validationResult['data'];

                        continue;
                    }

                    $invitation = $this->createInvitation($organization, $invitationData, $inviter);

                    // Send an invitation email if requested
                    if ($invitationData['send_email'] ?? true) {
                        try {
                            Mail::to($invitation->email)->send(new OrganizationInvitation($invitation));
                        } catch (Exception $e) {
                            // Log the error but don't fail the invitation creation
                            logger()->error('Failed to send invitation email', [
                                'invitation_id' => $invitation->id,
                                'email' => $invitation->email,
                                'error' => $e->getMessage(),
                            ]);
                        }
                    }

                    $results['successful'][] = [
                        'email' => $invitationData['email'],
                        'invitation_id' => $invitation->id,
                        'expires_at' => $invitation->expires_at,
                    ];
                } catch (Exception $e) {
                    $results['failed'][] = [
                        'email' => $invitationData['email'],
                        'reason' => 'Failed to create invitation: '.$e->getMessage(),
                    ];
                }
            }

            return $results;
        });
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
     * Export users to CSV or Excel format
     */
    public function exportUsers(Organization $organization, string $format = 'csv', array $filters = []): string
    {
        $result = $this->exportUsersExtended($organization, ['format' => $format] + $filters, auth()->user() ?? User::first());

        return $result['download_url'];
    }

    /**
     * Export users to CSV or Excel format (extended method)
     */
    public function exportUsersExtended(
        Organization $organization,
        array $options,
        User $currentUser
    ): array {
        $format = $options['format'] ?? 'csv';
        $includeRoles = $options['include_roles'] ?? true;
        $includeApplications = $options['include_applications'] ?? true;
        $includeActivity = $options['include_activity'] ?? false;

        // Build user query - filter by organization
        $query = User::where('organization_id', $organization->id);

        // Optionally filter by applications if specified
        if (! empty($options['application_ids'])) {
            $query->whereHas('applications', function ($q) use ($options) {
                $q->whereIn('application_id', $options['application_ids']);
            });
        }

        if (! empty($options['date_from']) && ! empty($options['date_to'])) {
            $query->whereBetween('created_at', [
                Carbon::parse($options['date_from'])->startOfDay(),
                Carbon::parse($options['date_to'])->endOfDay(),
            ]);
        }

        // Load relationships
        $with = [];
        if ($includeRoles) {
            $with[] = 'roles';
            $with[] = 'customRoles';
        }
        if ($includeApplications) {
            $with[] = 'applications';
        }

        $users = $query->with($with)->get();

        // Generate filename
        $filename = sprintf(
            'users_export_%s_%s.%s',
            $organization->slug,
            now()->format('Y-m-d_H-i-s'),
            $format
        );

        // Export using Laravel Excel or CSV
        $exportPath = 'exports/'.$filename;

        if ($format === 'xlsx') {
            Excel::store(new UsersExport($users, $includeRoles, $includeApplications, $includeActivity), $exportPath);
        } else {
            $this->generateCsvExport($users, $organization, $exportPath, $includeRoles, $includeApplications);
        }

        $downloadUrl = Storage::url($exportPath);

        return [
            'download_url' => $downloadUrl,
            'filename' => $filename,
            'users_count' => $users->count(),
            'format' => $format,
            'expires_at' => now()->addHours(24), // Files expire in 24 hours
        ];
    }

    /**
     * Import users from CSV or Excel file
     */
    public function importUsers(UploadedFile $file, Organization $organization, string $defaultRole): array
    {
        return $this->importUsersExtended($file, $organization, ['default_role' => $defaultRole], auth()->user() ?? User::first());
    }

    /**
     * Import users from CSV or Excel file (extended method)
     */
    public function importUsersExtended(
        UploadedFile $file,
        Organization $organization,
        array $options,
        User $currentUser
    ): array {
        $sendInvitations = $options['send_invitations'] ?? false;
        $defaultRole = $options['default_role'] ?? 'user';
        $updateExisting = $options['update_existing'] ?? false;

        $import = new UsersImport(
            $organization,
            $currentUser,
            $sendInvitations,
            $defaultRole,
            $updateExisting,
            $this->invitationService
        );

        Excel::import($import, $file);

        return $import->getResults();
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
     * Validate invitation data and check for conflicts
     */
    private function validateInvitationData(array $invitationData, Organization $organization): ?array
    {
        // Check if the user already exists
        $existingUser = User::where('email', $invitationData['email'])->first();
        if ($existingUser) {
            return [
                'type' => 'already_exists',
                'data' => [
                    'email' => $invitationData['email'],
                    'reason' => 'User already exists in the system',
                ],
            ];
        }

        // Check if an invitation already exists
        $existingInvitation = Invitation::where('organization_id', $organization->id)
            ->where('email', $invitationData['email'])
            ->pending()
            ->first();

        if ($existingInvitation) {
            return [
                'type' => 'already_exists',
                'data' => [
                    'email' => $invitationData['email'],
                    'reason' => 'Pending invitation already exists',
                ],
            ];
        }

        // Validate custom role if provided
        if (isset($invitationData['custom_role_id'])) {
            $customRole = CustomRole::where('id', $invitationData['custom_role_id'])
                ->where('organization_id', $organization->id)
                ->active()
                ->first();

            if (! $customRole) {
                return [
                    'type' => 'failed',
                    'data' => [
                        'email' => $invitationData['email'],
                        'reason' => 'Invalid custom role ID',
                    ],
                ];
            }
        }

        return null; // No validation errors
    }

    /**
     * Create an invitation record
     */
    private function createInvitation(Organization $organization, array $invitationData, User $inviter): Invitation
    {
        return Invitation::create([
            'organization_id' => $organization->id,
            'email' => $invitationData['email'],
            'role' => $invitationData['role'] ?? 'user',
            'inviter_id' => $inviter->id,
            'token' => Str::random(64),
            'expires_at' => now()->addDays($invitationData['expires_in_days'] ?? 7),
            'metadata' => array_merge($invitationData['metadata'] ?? [], [
                'custom_role_id' => $invitationData['custom_role_id'] ?? null,
                'bulk_invited' => true,
            ]),
        ]);
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
     * Generate CSV export
     */
    private function generateCsvExport(Collection $users, Organization $organization, string $exportPath, bool $includeRoles, bool $includeApplications): void
    {
        $csv = Writer::createFromFileObject(new SplTempFileObject);

        // Headers
        $headers = ['ID', 'Name', 'Email', 'Created At', 'Last Login', 'MFA Enabled', 'Status'];
        if ($includeRoles) {
            $headers[] = 'Roles';
            $headers[] = 'Custom Roles';
        }
        if ($includeApplications) {
            $headers[] = 'Applications';
        }

        $csv->insertOne($headers);

        // Data rows
        foreach ($users as $user) {
            $row = [
                $user->id,
                $user->name,
                $user->email,
                $user->created_at->format('Y-m-d H:i:s'),
                $user->last_login_at ? $user->last_login_at->format('Y-m-d H:i:s') : 'Never',
                $user->hasMfaEnabled() ? 'Yes' : 'No',
                $user->is_active ? 'Active' : 'Inactive',
            ];

            if ($includeRoles) {
                $row[] = $user->roles->pluck('name')->join(', ');
                $row[] = $user->customRoles->pluck('name')->join(', ');
            }

            if ($includeApplications) {
                $row[] = $user->applications->where('organization_id', $organization->id)->pluck('name')->join(', ');
            }

            $csv->insertOne($row);
        }

        $csvContent = $csv->toString();
        Storage::put($exportPath, $csvContent);
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
