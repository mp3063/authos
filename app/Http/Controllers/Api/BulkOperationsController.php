<?php

namespace App\Http\Controllers\Api;

use App\Exports\UsersExport;
use App\Http\Controllers\Controller;
use App\Imports\UsersImport;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Services\AuthenticationLogService;
use App\Services\InvitationService;
use Carbon\Carbon;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use League\Csv\Writer;
use Maatwebsite\Excel\Facades\Excel;
use Spatie\Activitylog\Models\Activity;
use SplTempFileObject;
use Throwable;

/**
 * BulkOperationsController handles bulk operations for organization management.
 *
 * Suppressing IDE warnings for Eloquent dynamic methods which are valid Laravel patterns:
 *
 * @method static Organization findOrFail(mixed $id)
 * @method static User where(string $column, mixed $value)
 * @method static User whereIn(string $column, array $values)
 * @method static User whereHas(string $relation, callable $callback)
 * @method static CustomRole create(array $attributes)
 */
class BulkOperationsController extends Controller
{
    protected AuthenticationLogService $oAuthService;

    protected InvitationService $invitationService;

    public function __construct(AuthenticationLogService $oAuthService, InvitationService $invitationService)
    {
        $this->authLogService = $oAuthService;
        $this->invitationService = $invitationService;
        $this->middleware('auth:api');
    }

    /**
     * Create a standardized validation error response
     */
    private function validationErrorResponse($validator): JsonResponse
    {
        return response()->json([
            'error' => 'validation_failed',
            'error_description' => 'The given data was invalid.',
            'details' => $validator->errors(),
        ], 422);
    }

    /**
     * Check if a user has permission to manage the specified organization
     */
    private function checkOrganizationPermission(User $user, Organization $organization): bool
    {
        return $user->isSuperAdmin() || $user->organization_id === $organization->id;
    }

    /**
     * Create a standardized forbidden response
     */
    private function forbiddenResponse(): JsonResponse
    {
        return response()->json([
            'error' => 'forbidden',
            'error_description' => 'You do not have permission to manage this organization.',
        ], 403);
    }

    /**
     * Bulk invite multiple users to an organization
     */
    public function bulkInviteUsers(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.create');

        $validator = Validator::make($request->all(), [
            'invitations' => 'required|array|min:1|max:100',
            'invitations.*.email' => 'required|email|max:255',
            'invitations.*.role' => 'required|string|max:255',
            'invitations.*.custom_role_id' => 'sometimes|integer|exists:custom_roles,id',
            'invitations.*.send_email' => 'sometimes|boolean',
            'invitations.*.expires_in_days' => 'sometimes|integer|min:1|max:30',
            'invitations.*.metadata' => 'sometimes|array',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator);
        }

        $organization = Organization::findOrFail($organizationId);
        $user = auth()->user();

        // Check if the user has permission to manage this organization
        if (! $this->checkOrganizationPermission($user, $organization)) {
            return $this->forbiddenResponse();
        }

        $results = [
            'successful' => [],
            'failed' => [],
            'already_exists' => [],
        ];

        try {
            DB::transaction(function () use ($request, $organization, $user, &$results) {
                foreach ($request->invitations as $invitationData) {
                    try {
                        // Check if the user already exists
                        $existingUser = User::where('email', $invitationData['email'])->first();
                        if ($existingUser) {
                            $results['already_exists'][] = [
                                'email' => $invitationData['email'],
                                'reason' => 'User already exists in the system',
                            ];

                            continue;
                        }

                        // Check if an invitation already exists
                        $existingInvitation = Invitation::where('organization_id', $organization->id)
                            ->where('email', $invitationData['email'])
                            ->pending()
                            ->first();

                        if ($existingInvitation) {
                            $results['already_exists'][] = [
                                'email' => $invitationData['email'],
                                'reason' => 'Pending invitation already exists',
                            ];

                            continue;
                        }

                        // Validate custom role if provided
                        if (isset($invitationData['custom_role_id'])) {
                            $customRole = CustomRole::where('id', $invitationData['custom_role_id'])
                                ->where('organization_id', $organization->id)
                                ->active()
                                ->first();

                            if (! $customRole) {
                                $results['failed'][] = [
                                    'email' => $invitationData['email'],
                                    'reason' => 'Invalid custom role ID',
                                ];

                                continue;
                            }
                        }

                        $invitation = Invitation::create([
                            'organization_id' => $organization->id,
                            'email' => $invitationData['email'],
                            'role' => $invitationData['role'] ?? 'user',
                            'inviter_id' => $user->id,  // Fixed: Use correct column name
                            'token' => \Illuminate\Support\Str::random(64),  // Generate unique token
                            'expires_at' => now()->addDays($invitationData['expires_in_days'] ?? 7),
                            'metadata' => array_merge($invitationData['metadata'] ?? [], [
                                'custom_role_id' => $invitationData['custom_role_id'] ?? null,
                                'bulk_invited' => true,
                            ]),
                        ]);

                        // Send an invitation email if requested
                        if ($invitationData['send_email'] ?? true) {
                            $this->invitationService->sendInvitation(
                                $organization->id,
                                $invitation->email,
                                $user->id,
                                $invitation->role,
                                $invitation->metadata ?? []
                            );
                        }

                        $results['successful'][] = [
                            'email' => $invitationData['email'],
                            'invitation_id' => $invitation->id,
                            'expires_at' => $invitation->expires_at,
                        ];

                        // Log invitation sent
                        $this->authLogService->logAuthenticationEvent(
                            $user,
                            'bulk_invitation_sent',
                            ['invitation_id' => $invitation->id],
                            $request
                        );
                    } catch (Exception $e) {
                        $results['failed'][] = [
                            'email' => $invitationData['email'],
                            'reason' => 'Failed to create invitation: '.$e->getMessage(),
                        ];
                    }
                }
            });
        } catch (Throwable $e) {
            return response()->json([
                'error' => 'transaction_failed',
                'error_description' => 'Failed to process bulk invitations: '.$e->getMessage(),
            ], 500);
        }

        return response()->json([
            'data' => $results,
            'message' => sprintf(
                'Bulk invitation completed: %d successful, %d failed, %d already exist',
                count($results['successful']),
                count($results['failed']),
                count($results['already_exists'])
            ),
        ]);
    }

    /**
     * Bulk assign roles to multiple users
     */
    public function bulkAssignRoles(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('roles.assign');

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:1000',
            'user_ids.*' => 'required|integer|exists:users,id',
            'roles' => 'sometimes|array',
            'roles.*' => 'string|exists:roles,name',
            'custom_roles' => 'sometimes|array',
            'custom_roles.*' => 'integer|exists:custom_roles,id',
            'action' => 'required|string|in:assign,revoke',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check if the user has permission to manage this organization
        if (! $this->checkOrganizationPermission($currentUser, $organization)) {
            return $this->forbiddenResponse();
        }

        $users = User::whereIn('id', $request->user_ids)->get();
        $roles = $request->input('roles', []);
        $customRoleIds = $request->input('custom_roles', []);
        $action = $request->input('action');

        // Validate that custom roles belong to the organization
        if (! empty($customRoleIds)) {
            $customRoles = CustomRole::whereIn('id', $customRoleIds)
                ->where('organization_id', $organization->id)
                ->active()
                ->get();

            if ($customRoles->count() !== count($customRoleIds)) {
                return response()->json([
                    'error' => 'validation_failed',
                    'error_description' => 'One or more custom roles do not belong to this organization.',
                ], 422);
            }
        }

        // Validate that all users belong to the organization
        $invalidUsers = $users->where('organization_id', '!=', $organization->id);
        if ($invalidUsers->count() > 0) {
            return response()->json([
                'message' => 'One or more users do not belong to this organization.',
                'invalid_users' => $invalidUsers->pluck('id'),
            ], 422);
        }

        $results = [
            'successful' => [],
            'failed' => [],
        ];

        try {
            DB::transaction(function () use ($users, $roles, $customRoleIds, $action, $organization, $currentUser, &$results) {
                foreach ($users as $user) {
                    try {
                        if ($action === 'assign') {
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
                        } else {
                            // Revoke standard roles
                            foreach ($roles as $role) {
                                if ($user->hasOrganizationRole($role, $organization->id)) {
                                    $user->removeOrganizationRole($role, $organization->id);
                                }
                            }

                            // Revoke custom roles
                            $user->customRoles()->detach($customRoleIds);
                        }

                        $results['successful'][] = [
                            'user_id' => $user->id,
                            'email' => $user->email,
                            'name' => $user->name,
                        ];
                    } catch (Exception $e) {
                        $results['failed'][] = [
                            'user_id' => $user->id,
                            'email' => $user->email,
                            'reason' => $e->getMessage(),
                        ];
                    }
                }
            });
        } catch (Throwable $e) {
            return response()->json([
                'error' => 'transaction_failed',
                'error_description' => 'Failed to process bulk role assignment: '.$e->getMessage(),
            ], 500);
        }

        // Log bulk role assignment
        $this->authLogService->logAuthenticationEvent(
            $currentUser,
            'bulk_role_'.$action,
            ['role_id' => $roleId, 'action' => $action, 'users_count' => count($validated['user_ids'])],
            $request
        );

        return response()->json([
            'data' => $results,
            'message' => sprintf(
                'Bulk role %s completed: %d successful, %d failed',
                $action,
                count($results['successful']),
                count($results['failed'])
            ),
        ]);
    }

    /**
     * Bulk revoke access for multiple users
     */
    public function bulkRevokeAccess(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.delete');

        $validator = Validator::make($request->all(), [
            'user_ids' => 'required|array|min:1|max:1000',
            'user_ids.*' => 'required|integer|exists:users,id',
            'application_ids' => 'sometimes|array',
            'application_ids.*' => 'integer|exists:applications,id',
            'revoke_tokens' => 'sometimes|boolean',
            'revoke_all_access' => 'sometimes|boolean',
            'reason' => 'sometimes|string|max:500',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check permissions
        if (! $this->checkOrganizationPermission($currentUser, $organization)) {
            return $this->forbiddenResponse();
        }

        $users = User::whereIn('id', $request->user_ids)->get();
        $applicationIds = $request->input('application_ids', []);
        $revokeTokens = $request->input('revoke_tokens', true);
        $revokeAllAccess = $request->input('revoke_all_access', false);

        $results = [
            'successful' => [],
            'failed' => [],
        ];

        try {
            DB::transaction(function () use ($users, $organization, $applicationIds, $revokeTokens, $revokeAllAccess, &$results, $request) {
                foreach ($users as $user) {
                    try {
                        if ($revokeAllAccess) {
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
                        } else {
                            // Remove specific application access
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

                        // Log access revocation
                        $this->authLogService->logAuthenticationEvent(
                            $user,
                            'bulk_access_revoked',
                            [],
                            $request
                        );

                        $results['successful'][] = [
                            'user_id' => $user->id,
                            'email' => $user->email,
                            'name' => $user->name,
                        ];
                    } catch (Exception $e) {
                        $results['failed'][] = [
                            'user_id' => $user->id,
                            'email' => $user->email,
                            'reason' => $e->getMessage(),
                        ];
                    }
                }
            });
        } catch (Throwable $e) {
            return response()->json([
                'error' => 'transaction_failed',
                'error_description' => 'Failed to process bulk access revocation: '.$e->getMessage(),
            ], 500);
        }

        // Log bulk revocation activity
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
                'reason' => $request->input('reason'),
            ],
        ]);

        return response()->json([
            'data' => $results,
            'message' => sprintf(
                'Bulk access revocation completed: %d successful, %d failed',
                count($results['successful']),
                count($results['failed'])
            ),
        ]);
    }

    /**
     * Export user data to CSV/Excel
     */
    public function exportUsers(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.read');

        $validator = Validator::make($request->all(), [
            'format' => 'sometimes|string|in:csv,xlsx',
            'include_roles' => 'sometimes|boolean',
            'include_applications' => 'sometimes|boolean',
            'include_activity' => 'sometimes|boolean',
            'date_from' => 'sometimes|date',
            'date_to' => 'sometimes|date|after_or_equal:date_from',
            'application_ids' => 'sometimes|array',
            'application_ids.*' => 'integer|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check permissions
        if (! $this->checkOrganizationPermission($currentUser, $organization)) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to export data from this organization.',
            ], 403);
        }

        $format = $request->input('format', 'csv');
        $includeRoles = $request->input('include_roles', true);
        $includeApplications = $request->input('include_applications', true);
        $includeActivity = $request->input('include_activity', false);

        try {
            // Build user query
            $query = User::whereHas('applications', function ($q) use ($organization, $request) {
                $q->where('organization_id', $organization->id);

                if ($request->has('application_ids')) {
                    $q->whereIn('application_id', $request->application_ids);
                }
            });

            if ($request->has('date_from') && $request->has('date_to')) {
                $query->whereBetween('created_at', [
                    Carbon::parse($request->date_from)->startOfDay(),
                    Carbon::parse($request->date_to)->endOfDay(),
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
                // CSV export
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

            $downloadUrl = Storage::url($exportPath);

            // Log export activity
            $this->authLogService->logAuthenticationEvent(
                $currentUser,
                'users_exported',
                ['format' => $format, 'users_count' => $users->count()],
                $request
            );

            return response()->json([
                'data' => [
                    'download_url' => $downloadUrl,
                    'filename' => $filename,
                    'users_count' => $users->count(),
                    'format' => $format,
                    'expires_at' => now()->addHours(24), // Files expire in 24 hours
                ],
                'message' => 'Export completed successfully',
            ]);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'export_failed',
                'error_description' => 'Failed to export users: '.$e->getMessage(),
            ], 500);
        }
    }

    /**
     * Import users from a CSV/Excel file
     */
    public function importUsers(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.create');

        $validator = Validator::make($request->all(), [
            'file' => 'required|file|mimes:csv,xlsx|max:10240', // 10MB max
            'send_invitations' => 'sometimes|boolean',
            'default_role' => 'sometimes|string',
            'default_custom_role_id' => 'sometimes|integer|exists:custom_roles,id',
            'update_existing' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check permissions
        if (! $this->checkOrganizationPermission($currentUser, $organization)) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to import users to this organization.',
            ], 403);
        }

        $sendInvitations = $request->input('send_invitations', false);
        $defaultRole = $request->input('default_role', 'user');
        $updateExisting = $request->input('update_existing', false);

        try {
            $import = new UsersImport(
                $organization,
                $currentUser,
                $sendInvitations,
                $defaultRole,
                $updateExisting,
                $this->invitationService
            );

            Excel::import($import, $request->file('file'));

            $results = $import->getResults();

            // Log import activity
            $this->authLogService->logAuthenticationEvent(
                $currentUser,
                'users_imported',
                ['imported_count' => $results['imported'] ?? 0, 'failed_count' => $results['failed'] ?? 0],
                $request
            );

            return response()->json([
                'data' => $results,
                'message' => sprintf(
                    'Import completed: %d created, %d updated, %d invited, %d failed',
                    count($results['created']),
                    count($results['updated']),
                    count($results['invited']),
                    count($results['failed'])
                ),
            ]);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'import_failed',
                'error_description' => 'Failed to import users: '.$e->getMessage(),
            ], 500);
        }
    }
}
