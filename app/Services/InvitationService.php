<?php

namespace App\Services;

use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Mail\OrganizationInvitation;
use App\Mail\InvitationAccepted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;
use Exception;

class InvitationService
{
    public function sendInvitation(
        int $organizationId, 
        string $email, 
        int $inviterId,
        string $role = 'user',
        array $metadata = []
    ): Invitation {
        $organization = Organization::findOrFail($organizationId);
        $inviter = User::findOrFail($inviterId);

        // Validate that the inviter has permission to invite to this organization
        if (!$this->canInviteToOrganization($inviter, $organization)) {
            throw new Exception('User does not have permission to invite users to this organization');
        }

        // Check if user is already a member of the organization
        if ($this->isUserInOrganization($email, $organizationId)) {
            throw ValidationException::withMessages([
                'email' => 'User is already a member of this organization'
            ]);
        }

        // Check for existing pending invitation
        $existingInvitation = Invitation::where('organization_id', $organizationId)
            ->where('email', $email)
            ->pending()
            ->first();

        if ($existingInvitation) {
            throw ValidationException::withMessages([
                'email' => 'A pending invitation already exists for this email address'
            ]);
        }

        // Create the invitation
        $invitation = Invitation::create([
            'organization_id' => $organizationId,
            'email' => $email,
            'role' => $role,
            'invited_by' => $inviterId,
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
                'error' => $e->getMessage()
            ]);
        }

        return $invitation;
    }

    public function acceptInvitation(string $token, User $user): bool
    {
        $invitation = Invitation::where('token', $token)->first();

        if (!$invitation) {
            throw new Exception('Invalid invitation token');
        }

        if (!$invitation->isPending()) {
            throw new Exception('Invitation has expired or already been accepted');
        }

        // Check if user is already in the organization
        if ($user->organization_id === $invitation->organization_id) {
            throw new Exception('User is already a member of this organization');
        }

        return DB::transaction(function () use ($invitation, $user) {
            // Accept the invitation
            $invitation->accept($user);

            // Add user to organization if not already a member
            if (!$user->organization_id) {
                $user->update(['organization_id' => $invitation->organization_id]);
            }

            // Assign the role to the user
            $user->assignOrganizationRole($invitation->role, $invitation->organization_id);

            // Notify the inviter
            try {
                Mail::to($invitation->inviter->email)->send(
                    new InvitationAccepted($invitation, $user)
                );
            } catch (Exception $e) {
                logger()->error('Failed to send invitation accepted email', [
                    'invitation_id' => $invitation->id,
                    'error' => $e->getMessage()
                ]);
            }

            return true;
        });
    }

    public function cancelInvitation(int $invitationId, User $canceller): bool
    {
        $invitation = Invitation::findOrFail($invitationId);

        // Check if user has permission to cancel this invitation
        if (!$this->canManageInvitation($canceller, $invitation)) {
            throw new Exception('User does not have permission to cancel this invitation');
        }

        return $invitation->delete();
    }

    public function resendInvitation(int $invitationId, User $sender): Invitation
    {
        $invitation = Invitation::findOrFail($invitationId);

        // Check if user has permission to resend this invitation
        if (!$this->canManageInvitation($sender, $invitation)) {
            throw new Exception('User does not have permission to resend this invitation');
        }

        if (!$invitation->isPending()) {
            throw new Exception('Cannot resend a non-pending invitation');
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
                'error' => $e->getMessage()
            ]);
        }

        return $invitation;
    }

    public function bulkInvite(
        int $organizationId, 
        array $invitations, 
        int $inviterId
    ): array {
        $results = [];
        $organization = Organization::findOrFail($organizationId);
        $inviter = User::findOrFail($inviterId);

        if (!$this->canInviteToOrganization($inviter, $organization)) {
            throw new Exception('User does not have permission to invite users to this organization');
        }

        foreach ($invitations as $inviteData) {
            try {
                $invitation = $this->sendInvitation(
                    $organizationId,
                    $inviteData['email'],
                    $inviterId,
                    $inviteData['role'] ?? 'user',
                    $inviteData['metadata'] ?? []
                );

                $results[] = [
                    'email' => $inviteData['email'],
                    'status' => 'success',
                    'invitation_id' => $invitation->id
                ];
            } catch (Exception $e) {
                $results[] = [
                    'email' => $inviteData['email'],
                    'status' => 'error',
                    'message' => $e->getMessage()
                ];
            }
        }

        return $results;
    }

    public function getOrganizationInvitations(
        int $organizationId, 
        User $user,
        string $status = 'all'
    ) {
        $organization = Organization::findOrFail($organizationId);

        if (!$this->canViewInvitations($user, $organization)) {
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

    private function canInviteToOrganization(User $user, Organization $organization): bool
    {
        // Super admins can invite to any organization
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization owners and admins can invite
        if ($user->organization_id === $organization->id) {
            return $user->isOrganizationOwner() || $user->isOrganizationAdmin();
        }

        return false;
    }

    private function canManageInvitation(User $user, Invitation $invitation): bool
    {
        // Super admins can manage any invitation
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can manage invitations in their own organization
        if ($user->organization_id === $invitation->organization_id) {
            return $user->isOrganizationOwner() || 
                   $user->isOrganizationAdmin() || 
                   $user->id === $invitation->invited_by;
        }

        return false;
    }

    private function canViewInvitations(User $user, Organization $organization): bool
    {
        // Super admins can view all invitations
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can view invitations in their own organization
        if ($user->organization_id === $organization->id) {
            return $user->isOrganizationOwner() || $user->isOrganizationAdmin();
        }

        return false;
    }

    private function isUserInOrganization(string $email, int $organizationId): bool
    {
        return User::where('email', $email)
            ->where('organization_id', $organizationId)
            ->exists();
    }

    public function cleanupExpiredInvitations(): int
    {
        return Invitation::expired()->delete();
    }
}