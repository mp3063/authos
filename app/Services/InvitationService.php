<?php

namespace App\Services;

use App\Mail\OrganizationInvitation;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;

class InvitationService
{
    public function __construct(
        protected InvitationAuthorizer $authorizer,
        protected InvitationAcceptanceService $acceptance,
    ) {}

    public function sendInvitation(
        int $organizationId,
        string $email,
        $inviter, // Can be User instance or int
        string $role = 'user',
        array $metadata = [],
        bool $preventDuplicates = false
    ): Invitation {
        $organization = Organization::findOrFail($organizationId);

        // Handle inviter - can be User instance or ID
        if ($inviter instanceof User) {
            $inviterUser = $inviter;
            $inviterId = $inviter->id;
        } else {
            $inviterId = $inviter;
            $inviterUser = User::with('roles')->findOrFail($inviterId);
        }

        // Ensure permissions team context is set for the inviter
        $inviterUser->setPermissionsTeamId($inviterUser->organization_id);

        // Validate that the inviter has permission to invite to this organization
        if (! $this->authorizer->canInviteToOrganization($inviterUser, $organization)) {
            throw new Exception('User does not have permission to invite users to this organization');
        }

        // Check if user is already a member of the organization
        if ($this->isUserInOrganization($email, $organizationId)) {
            throw ValidationException::withMessages([
                'email' => 'User is already a member of this organization',
            ]);
        }

        // Check for existing pending invitation
        $existingInvitation = Invitation::where('organization_id', $organizationId)
            ->where('email', $email)
            ->pending()
            ->first();

        if ($existingInvitation) {
            if ($preventDuplicates) {
                throw ValidationException::withMessages([
                    'email' => 'A pending invitation for this email already exists in this organization',
                ]);
            } else {
                // Delete existing pending invitation to replace it
                $existingInvitation->delete();
            }
        }

        // Create the invitation
        $invitation = Invitation::create([
            'organization_id' => $organizationId,
            'email' => $email,
            'role' => $role,
            'inviter_id' => $inviterId,
            'metadata' => $metadata,
        ]);

        // Send invitation email
        try {
            Mail::to($email)->send(new OrganizationInvitation($invitation));
        } catch (Exception $e) {
            // Log the error but don't fail the invitation creation
            logger()->error('Failed to send invitation email', [
                'invitation_id' => $invitation->id,
                'email' => $email,
                'error' => $e->getMessage(),
            ]);
        }

        return $invitation;
    }

    public function acceptInvitation(string $token, array $userData): User
    {
        return $this->acceptance->acceptAsNewUser($token, $userData);
    }

    /**
     * Accept an invitation for an existing authenticated user
     */
    public function acceptInvitationAsExistingUser(string $token, User $user): bool
    {
        return $this->acceptance->acceptAsExistingUser($token, $user);
    }

    public function declineInvitation(string $token, ?string $reason = null): bool
    {
        return $this->acceptance->decline($token, $reason);
    }

    public function cancelInvitation(int $invitationId, User $canceller): bool
    {
        // Ensure permissions context is set
        $canceller->setPermissionsTeamId($canceller->organization_id);

        // Find invitation that belongs to the user's organization
        $invitation = Invitation::where('id', $invitationId)
            ->where('organization_id', $canceller->organization_id)
            ->first();

        if (! $invitation) {
            throw new ModelNotFoundException('Invitation not found');
        }

        // Check if user has permission to cancel this invitation
        if (! $this->authorizer->canManageInvitation($canceller, $invitation)) {
            throw new Exception('Not authorized to cancel this invitation');
        }

        return $invitation->markAsCancelled($canceller);
    }

    public function resendInvitation(int $invitationId, User $sender): Invitation
    {
        $invitation = Invitation::findOrFail($invitationId);

        // Ensure permissions context is set
        $sender->setPermissionsTeamId($sender->organization_id);

        // Check if user has permission to resend this invitation
        if (! $this->authorizer->canManageInvitation($sender, $invitation)) {
            throw new Exception('User does not have permission to resend this invitation');
        }

        // Only allow resending if invitation is pending or expired (but not accepted)
        if ($invitation->status === 'accepted') {
            throw new Exception('Cannot resend an accepted invitation');
        }

        // Extend expiry and generate new token
        $invitation->extend();
        $invitation->generateNewToken();

        // Send invitation email
        try {
            Mail::to($invitation->email)->send(new OrganizationInvitation($invitation));
        } catch (Exception $e) {
            logger()->error('Failed to resend invitation email', [
                'invitation_id' => $invitation->id,
                'error' => $e->getMessage(),
            ]);
        }

        return $invitation;
    }

    public function bulkInvite(
        int $organizationId,
        array $invitations,
        $inviter // Can be User instance or int for backward compatibility
    ): array {
        // Add validation for maximum batch size
        if (count($invitations) > 100) {
            throw ValidationException::withMessages([
                'invitations' => 'Cannot invite more than 100 users at once',
            ]);
        }

        $successful = [];
        $failed = [];
        $organization = Organization::findOrFail($organizationId);

        // Handle inviter - can be User instance or ID for backward compatibility
        if ($inviter instanceof User) {
            $inviterUser = $inviter;
        } else {
            $inviterUser = User::with('roles')->findOrFail($inviter);
        }

        // Set permissions team context
        $inviterUser->setPermissionsTeamId($inviterUser->organization_id);

        if (! $this->authorizer->canInviteToOrganization($inviterUser, $organization)) {
            throw new Exception('User does not have permission to invite users to this organization');
        }

        foreach ($invitations as $inviteData) {
            try {
                $invitation = $this->sendInvitation(
                    $organizationId,
                    $inviteData['email'],
                    $inviterUser, // Pass user instance
                    $inviteData['role'] ?? 'user',
                    $inviteData['metadata'] ?? [],
                    true // Prevent duplicates for API bulk operations
                );

                $successful[] = [
                    'email' => $inviteData['email'],
                    'status' => 'success',
                    'invitation_id' => $invitation->id,
                ];
            } catch (Exception $e) {
                $failed[] = [
                    'email' => $inviteData['email'],
                    'status' => 'error',
                    'error' => $e->getMessage(),
                ];
            }
        }

        return [
            'successful' => $successful,
            'failed' => $failed,
        ];
    }

    public function getOrganizationInvitations(
        int $organizationId,
        User $user,
        string $status = 'all'
    ): mixed {
        $organization = Organization::findOrFail($organizationId);

        // Ensure permissions context is set
        $user->setPermissionsTeamId($user->organization_id);

        if (! $this->authorizer->canViewInvitations($user, $organization)) {
            throw new Exception('User does not have permission to view invitations for this organization');
        }

        $query = $organization->invitations()
            ->with(['inviter', 'acceptor', 'organization']);

        switch ($status) {
            case 'pending':
                $query->pending();
                break;
            case 'expired':
                $query->expired();
                break;
            case 'accepted':
                $query->accepted();
                break;
        }

        return $query->orderBy('created_at', 'desc')->get();
    }

    public function getPendingInvitations(int $organizationId): mixed
    {
        return Invitation::where('organization_id', $organizationId)
            ->pending()
            ->with(['inviter', 'organization'])
            ->orderBy('created_at', 'desc')
            ->get();
    }

    private function isUserInOrganization(string $email, int $organizationId): bool
    {
        return User::where('email', $email)
            ->where('organization_id', $organizationId)
            ->exists();
    }

    public function cleanupExpiredInvitations(): int
    {
        return Invitation::expired()->delete() ?: 0;
    }
}
