<?php

namespace App\Services;

use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;

class InvitationAuthorizer
{
    public function canInviteToOrganization(User $user, Organization $organization): bool
    {
        // Super admins can invite to any organization
        if ($user->isSuperAdmin()) {
            return true;
        }

        if ($user->organization_id !== $organization->id) {
            return false;
        }

        return $this->canManageInvitations($user);
    }

    public function canManageInvitation(User $user, Invitation $invitation): bool
    {
        // Super admins can manage any invitation
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can manage invitations in their own organization
        if ($user->organization_id !== $invitation->organization_id) {
            return false;
        }

        return $this->canManageInvitations($user) || $user->id === $invitation->inviter_id;
    }

    public function canViewInvitations(User $user, Organization $organization): bool
    {
        // Super admins can view all invitations
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Users can view invitations in their own organization
        if ($user->organization_id !== $organization->id) {
            return false;
        }

        return $this->canManageInvitations($user);
    }

    private function canManageInvitations(User $user): bool
    {
        return $user->hasOrganizationPermission('users.create');
    }
}
