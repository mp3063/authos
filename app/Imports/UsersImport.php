<?php

namespace App\Imports;

use App\Models\User;
use App\Models\Organization;
use App\Models\Invitation;
use App\Models\CustomRole;
use App\Services\InvitationService;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Maatwebsite\Excel\Concerns\ToCollection;
use Maatwebsite\Excel\Concerns\WithHeadingRow;
use Maatwebsite\Excel\Concerns\WithValidation;

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
        bool $sendInvitations = false, 
        string $defaultRole = 'user', 
        bool $updateExisting = false,
        InvitationService $invitationService
    ) {
        $this->organization = $organization;
        $this->currentUser = $currentUser;
        $this->sendInvitations = $sendInvitations;
        $this->defaultRole = $defaultRole;
        $this->updateExisting = $updateExisting;
        $this->invitationService = $invitationService;
    }

    public function collection(Collection $rows)
    {
        foreach ($rows as $row) {
            try {
                $this->processRow($row);
            } catch (\Exception $e) {
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
                'reason' => 'Validation failed: ' . $validator->errors()->first(),
            ];
            return;
        }

        $email = strtolower(trim($rowData['email']));
        $name = trim($rowData['name']);
        $password = $rowData['password'] ?? null;
        $role = $rowData['role'] ?? $this->defaultRole;
        $customRole = $rowData['custom_role'] ?? null;

        // Check if user already exists
        $existingUser = User::where('email', $email)->first();

        if ($existingUser) {
            if ($this->updateExisting) {
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
        if (!$password && $this->sendInvitations) {
            $this->createInvitation($email, $name, $role, $customRole, $rowData);
            return;
        }

        // Create new user
        if ($password) {
            $this->createUser($email, $name, $password, $role, $customRole, $rowData);
        } else {
            $this->results['failed'][] = [
                'row' => $rowData,
                'reason' => 'No password provided and send_invitations is false',
            ];
        }
    }

    protected function createUser(string $email, string $name, string $password, string $role, ?string $customRole, array $rowData)
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
            try {
                $user->assignOrganizationRole($role, $this->organization->id);
            } catch (\Exception $e) {
                // If role assignment fails, try to assign default user role
                try {
                    $user->assignOrganizationRole('user', $this->organization->id);
                } catch (\Exception $e2) {
                    // Log the error but don't fail the import
                }
            }
        }

        // Assign custom role if provided
        if ($customRole) {
            $customRoleModel = CustomRole::where('organization_id', $this->organization->id)
                ->where('name', $customRole)
                ->active()
                ->first();

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

        if (!empty($rowData['name']) && $rowData['name'] !== $user->name) {
            $updateData['name'] = trim($rowData['name']);
        }

        if (!empty($rowData['password'])) {
            $updateData['password'] = Hash::make($rowData['password']);
        }

        if (!empty($updateData)) {
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
            $customRoleModel = CustomRole::where('organization_id', $this->organization->id)
                ->where('name', $customRole)
                ->active()
                ->first();
            $customRoleId = $customRoleModel?->id;
        }

        $invitation = Invitation::create([
            'organization_id' => $this->organization->id,
            'email' => $email,
            'role' => $role,
            'inviter_id' => $this->currentUser->id,
            'token' => \Illuminate\Support\Str::random(64),
            'expires_at' => now()->addDays(7),
            'metadata' => [
                'imported_name' => $name,
                'custom_role_id' => $customRoleId,
                'bulk_imported' => true,
            ],
        ]);

        // Send invitation email
        try {
            \Illuminate\Support\Facades\Mail::to($invitation->email)
                ->send(new \App\Mail\OrganizationInvitation($invitation));
        } catch (\Exception $e) {
            // Log email failure but don't fail the import
            logger()->error('Failed to send invitation email during import', [
                'invitation_id' => $invitation->id,
                'email' => $invitation->email,
                'error' => $e->getMessage()
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
}