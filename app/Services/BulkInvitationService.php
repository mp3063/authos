<?php

namespace App\Services;

use App\Mail\OrganizationInvitation;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class BulkInvitationService
{
    public function __construct(protected UserRoleService $userRoles) {}

    /**
     * Bulk invite multiple users to an organization
     */
    public function inviteUsers(array $invitations, Organization $organization, string $roleId, User $caller): array
    {
        $results = [
            'successful' => [],
            'failed' => [],
            'already_exists' => [],
        ];

        return DB::transaction(function () use ($organization, $invitations, $caller, $roleId, &$results) {
            foreach ($invitations as $invitationData) {
                try {
                    // Ensure invitationData is properly formatted
                    if (is_string($invitationData)) {
                        $invitationData = ['email' => $invitationData, 'role' => $roleId];
                    } else {
                        $invitationData['role'] = $invitationData['role'] ?? $roleId;
                    }

                    // Validate invitation requirements
                    $validationResult = $this->validateInvitationData($invitationData, $organization, $caller);
                    if ($validationResult) {
                        $results[$validationResult['type']][] = $validationResult['data'];

                        continue;
                    }

                    $invitation = $this->createInvitation($organization, $invitationData, $caller);

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
                    report($e);

                    $results['failed'][] = [
                        'email' => $invitationData['email'],
                        'reason' => 'Failed to create invitation',
                    ];
                }
            }

            return $results;
        });
    }

    /**
     * Validate invitation data and check for conflicts
     */
    private function validateInvitationData(array $invitationData, Organization $organization, User $inviter): ?array
    {
        if (! $this->userRoles->canGrantRoleNamed($inviter, $organization->id, $invitationData['role'] ?? 'user')) {
            return [
                'type' => 'failed',
                'data' => [
                    'email' => $invitationData['email'],
                    'reason' => 'You cannot invite users with this role',
                ],
            ];
        }

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
}
