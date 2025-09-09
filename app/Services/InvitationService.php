<?php

namespace App\Services;

use App\Mail\InvitationAccepted;
use App\Mail\OrganizationInvitation;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\ValidationException;

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
        if (! $this->canInviteToOrganization($inviter, $organization)) {
            throw new Exception('User does not have permission to invite users to this organization');
        }

        // Check if user is already a member of the organization
        if ($this->isUserInOrganization($email, $organizationId)) {
            throw ValidationException::withMessages([
                'email' => 'User is already a member of this organization',
            ]);
        }

        // Check for existing pending invitation and delete it if exists
        $existingInvitation = Invitation::where('organization_id', $organizationId)
            ->where('email', $email)
            ->pending()
            ->first();

        if ($existingInvitation) {
            $existingInvitation->delete();
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
        $invitation = Invitation::where('token', $token)->first();

        if (! $invitation) {
            throw new Exception('Invalid or expired invitation');
        }

        if (! $invitation->isPending()) {
            throw new Exception($invitation->isExpired() ? 'Invalid or expired invitation' : 'Invitation has already been accepted');
        }

        return DB::transaction(function () use ($invitation, $userData) {
            // Create new user with invitation email and provided data
            $user = User::create([
                'name' => $userData['name'],
                'email' => $invitation->email,
                'password' => bcrypt($userData['password']),
                'organization_id' => $invitation->organization_id,
                'email_verified_at' => now(),
            ]);

            // Accept the invitation
            $invitation->accept($user);

            // Assign the role to the user
            if (method_exists($user, 'assignRole')) {
                $user->assignRole($invitation->role);
            }

            // Notify the inviter
            try {
                if ($invitation->inviter) {
                    Mail::to($invitation->inviter->email)->send(
                        new InvitationAccepted($invitation, $user)
                    );
                }
            } catch (Exception $e) {
                logger()->error('Failed to send invitation accepted email', [
                    'invitation_id' => $invitation->id,
                    'error' => $e->getMessage(),
                ]);
            }

            return $user;
        });
    }

    public function cancelInvitation(int $invitationId, User $canceller): bool
    {
        $invitation = Invitation::findOrFail($invitationId);

        // Check if user has permission to cancel this invitation
        if (! $this->canManageInvitation($canceller, $invitation)) {
            throw new Exception('Not authorized to cancel this invitation');
        }

        return $invitation->markAsCancelled($canceller);
    }

    public function resendInvitation(int $invitationId, User $sender): Invitation
    {
        $invitation = Invitation::findOrFail($invitationId);

        // Check if user has permission to resend this invitation
        if (! $this->canManageInvitation($sender, $invitation)) {
            throw new Exception('User does not have permission to resend this invitation');
        }

        if (! $invitation->isPending()) {
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
                'error' => $e->getMessage(),
            ]);
        }

        return $invitation;
    }

    public function bulkInvite(
        int $organizationId,
        array $invitations,
        int $inviterId
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
        $inviter = User::findOrFail($inviterId);

        if (! $this->canInviteToOrganization($inviter, $organization)) {
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
    ) {
        $organization = Organization::findOrFail($organizationId);

        if (! $this->canViewInvitations($user, $organization)) {
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

    public function getPendingInvitations(int $organizationId)
    {
        return Invitation::where('organization_id', $organizationId)
            ->pending()
            ->with(['inviter', 'organization'])
            ->orderBy('created_at', 'desc')
            ->get();
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
                   $user->id === $invitation->inviter_id;
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
