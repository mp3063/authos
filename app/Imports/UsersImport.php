<?php

namespace App\Imports;

use App\Mail\OrganizationInvitation;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\InvitationService;
use App\Services\UserRoleService;
use Exception;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Maatwebsite\Excel\Concerns\ToCollection;
use Maatwebsite\Excel\Concerns\WithHeadingRow;
use Spatie\Permission\PermissionRegistrar;

class UsersImport implements ToCollection, WithHeadingRow
{
    protected Organization $organization;

    protected User $currentUser;

    protected bool $sendInvitations;

    protected string $defaultRole;

    protected bool $updateExisting;

    protected InvitationService $invitationService;

    protected array $results = [
        'created' => [],
        'updated' => [],
        'invited' => [],
        'failed' => [],
    ];

    public function __construct(
        Organization $organization,
        User $currentUser,
        bool $sendInvitations,
        string $defaultRole,
        bool $updateExisting,
        InvitationService $invitationService,
        protected UserRoleService $userRoleService
    ) {
        $this->organization = $organization;
        $this->currentUser = $currentUser;
        $this->sendInvitations = $sendInvitations;
        $this->defaultRole = $defaultRole;
        $this->updateExisting = $updateExisting;
        $this->invitationService = $invitationService;
    }

    public function collection(Collection $rows): void
    {
        foreach ($rows as $row) {
            try {
                $this->processRow($row);
            } catch (Exception $e) {
                $this->results['failed'][] = [
                    'row' => $row->toArray(),
                    'reason' => $e->getMessage(),
                ];
            }
        }
    }

    protected function processRow(Collection $row)
    {
        $rowData = $row->toArray();

        // Validate required fields
        $validator = Validator::make($rowData, [
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255',
            'password' => 'sometimes|string|min:8',
            'role' => 'sometimes|string',
            'custom_role' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            $this->results['failed'][] = [
                'row' => $rowData,
                'reason' => 'Validation failed: '.$validator->errors()->first(),
            ];

            return;
        }

        $email = strtolower(trim($rowData['email']));
        $name = trim($rowData['name']);
        $password = $rowData['password'] ?? null;
        $role = $rowData['role'] ?? $this->defaultRole;
        $customRole = $rowData['custom_role'] ?? null;

        // Validate role exists for the organization
        if ($role && ! $this->isValidRole($role)) {
            $this->results['failed'][] = [
                'row' => $rowData,
                'reason' => "Invalid role: '{$role}' does not exist for this organization",
            ];

            return;
        }

        if ($denial = $this->grantDenial($role, $customRole)) {
            $this->results['failed'][] = ['row' => $rowData, 'reason' => $denial];

            return;
        }

        // Check if user already exists
        $existingUser = User::where('email', $email)->first();

        if ($existingUser) {
            if ($existingUser->organization_id !== $this->organization->id) {
                $this->results['failed'][] = ['row' => $rowData, 'reason' => 'Email address is already in use'];
            } elseif ($this->updateExisting && $this->exceedsCaller($existingUser)) {
                $this->results['failed'][] = [
                    'row' => $rowData,
                    'reason' => 'You cannot update a user with permissions you do not have',
                ];
            } elseif ($this->updateExisting) {
                $this->updateExistingUser($existingUser, $rowData);
            } else {
                $this->results['failed'][] = [
                    'row' => $rowData,
                    'reason' => 'User already exists and update_existing is false',
                ];
            }

            return;
        }

        // If no password provided and sending invitations, create invitation instead
        if (! $password && $this->sendInvitations) {
            $this->createInvitation($email, $name, $role, $customRole, $rowData);

            return;
        }

        // Create new user
        if ($password) {
            $this->createUser($email, $name, $password, $role, $customRole);
        } else {
            $this->results['failed'][] = [
                'row' => $rowData,
                'reason' => 'No password provided and send_invitations is false',
            ];
        }
    }

    protected function createUser(string $email, string $name, string $password, string $role, ?string $customRole)
    {
        $user = User::create([
            'name' => $name,
            'email' => $email,
            'password' => Hash::make($password),
            'organization_id' => $this->organization->id,
            'is_active' => true,
            'email_verified_at' => now(), // Auto-verify imported users
        ]);

        // Assign role
        if ($role) {
            $this->assignRoleToUser($user, $role);
        }

        // Assign custom role if provided
        if ($customRole) {
            $customRoleModel = $this->findCustomRole($customRole);

            if ($customRoleModel) {
                $user->customRoles()->attach($customRoleModel->id, [
                    'granted_at' => now(),
                    'granted_by' => $this->currentUser->id,
                ]);
            }
        }

        $this->results['created'][] = [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $role,
            'custom_role' => $customRole,
        ];
    }

    protected function updateExistingUser(User $user, array $rowData)
    {
        $updateData = [];

        if (! empty($rowData['name']) && $rowData['name'] !== $user->name) {
            $updateData['name'] = trim($rowData['name']);
        }

        if (! empty($updateData)) {
            $user->update($updateData);
        }

        $this->results['updated'][] = [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'updated_fields' => array_keys($updateData),
        ];
    }

    protected function createInvitation(string $email, string $name, string $role, ?string $customRole, array $rowData)
    {
        // Check if invitation already exists
        $existingInvitation = Invitation::where('organization_id', $this->organization->id)
            ->where('email', $email)
            ->pending()
            ->first();

        if ($existingInvitation) {
            $this->results['failed'][] = [
                'row' => $rowData,
                'reason' => 'Pending invitation already exists',
            ];

            return;
        }

        $customRoleId = null;
        if ($customRole) {
            $customRoleId = $this->findCustomRole($customRole)?->id;
        }

        $invitation = Invitation::create([
            'organization_id' => $this->organization->id,
            'email' => $email,
            'role' => $role,
            'inviter_id' => $this->currentUser->id,
            'token' => Str::random(64),
            'expires_at' => now()->addDays(7),
            'metadata' => [
                'imported_name' => $name,
                'custom_role_id' => $customRoleId,
                'bulk_imported' => true,
            ],
        ]);

        // Send invitation email
        try {
            Mail::to($invitation->email)
                ->send(new OrganizationInvitation($invitation));
        } catch (Exception $e) {
            // Log email failure but don't fail the import
            logger()->error('Failed to send invitation email during import', [
                'invitation_id' => $invitation->id,
                'email' => $invitation->email,
                'error' => $e->getMessage(),
            ]);
        }

        $this->results['invited'][] = [
            'email' => $email,
            'name' => $name,
            'invitation_id' => $invitation->id,
            'role' => $role,
            'custom_role' => $customRole,
            'expires_at' => $invitation->expires_at,
        ];
    }

    public function getResults(): array
    {
        return $this->results;
    }

    protected function isValidRole(string $role): bool
    {
        return $this->findRole($role) !== null;
    }

    protected function assignRoleToUser(User $user, string $role): void
    {
        $roleModel = $this->findRole($role);

        if ($roleModel) {
            // Set the team context for proper role assignment
            $user->setPermissionsTeamId($this->organization->id);
            app(PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);

            // Assign the role using Spatie's method
            $user->assignRole($roleModel);
        } else {
            throw new Exception("Role '$role' does not exist for organization {$this->organization->id}");
        }
    }

    protected function findRole(string $role): ?Role
    {
        return Role::whereRaw('LOWER(name) = LOWER(?)', [$role])
            ->where(function ($query) {
                $query->where('organization_id', $this->organization->id);

                if ($this->currentUser->isSuperAdmin()) {
                    $query->orWhereNull('organization_id');
                }
            })
            ->first();
    }

    protected function findCustomRole(string $customRole): ?CustomRole
    {
        return CustomRole::where('organization_id', $this->organization->id)
            ->where('name', $customRole)
            ->active()
            ->first();
    }

    protected function grantDenial(?string $role, ?string $customRole): ?string
    {
        $roleModel = $role ? $this->findRole($role) : null;
        if ($roleModel && $this->userRoleService->roleChangeDenial($this->currentUser, null, new EloquentCollection([$roleModel]))) {
            return "You cannot grant the role '{$role}'";
        }

        $customRoleModel = $customRole ? $this->findCustomRole($customRole) : null;
        if ($customRoleModel && $this->userRoleService->exceedsPermissionsOf($this->currentUser, collect($customRoleModel->permissions ?? []))) {
            return "You cannot grant the custom role '{$customRole}'";
        }

        return null;
    }

    protected function exceedsCaller(User $user): bool
    {
        return $this->userRoleService->exceedsPermissionsOf(
            $this->currentUser,
            $this->userRoleService->effectivePermissionNames($user)
        );
    }
}
