<?php

namespace App\Services;

use App\Mail\InvitationAccepted;
use App\Models\Invitation;
use App\Models\User;
use Exception;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

class InvitationAcceptanceService
{
    public function __construct(protected UserRoleService $userRoles) {}

    /**
     * Accept an invitation for an existing authenticated user
     */
    public function acceptAsExistingUser(string $token, User $user): bool
    {
        $invitation = Invitation::where('token', $token)->first();

        if (! $invitation) {
            throw new Exception('Invalid or expired invitation');
        }

        if (! $invitation->isPending()) {
            throw new Exception($invitation->isExpired() ? 'Invitation has expired' : 'Invitation already accepted');
        }

        // Verify the invitation email matches the user's email
        if ($invitation->email !== $user->email) {
            throw new Exception('Invitation email does not match your account email');
        }

        if ($user->organization_id !== $invitation->organization_id) {
            throw new Exception('This invitation is for a different organization than your account');
        }

        return DB::transaction(function () use ($invitation, $user) {
            // Accept the invitation
            $invitation->accept($user);

            // Assign the role to the user if they don't already have it
            if ($invitation->role) {
                $this->assignInvitedRole($user, $invitation);
            }

            $this->notifyInviter($invitation, $user);

            return true;
        });
    }

    /**
     * @throws Exception when the role carries permissions the inviter can no longer grant
     */
    private function assignInvitedRole(User $user, Invitation $invitation): void
    {
        $inviter = $invitation->inviter;
        $role = $inviter
            ? $this->userRoles->findAssignableRole($inviter, $invitation->organization_id, $invitation->role, $user->getDefaultGuardName())
            : null;

        if (! $role) {
            logger()->warning('Unable to assign role during invitation acceptance', [
                'role' => $invitation->role,
                'user_id' => $user->id,
            ]);

            return;
        }

        if ($this->userRoles->roleChangeDenial($inviter, $user, new EloquentCollection([$role]))) {
            throw new Exception('The invited role grants permissions the inviter cannot grant');
        }

        $this->userRoles->assignRole($user, (string) $role->id);
    }

    private function notifyInviter(Invitation $invitation, User $user): void
    {
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
    }

    public function decline(string $token, ?string $reason = null): bool
    {
        $invitation = Invitation::where('token', $token)->first();

        if (! $invitation) {
            throw new Exception('Invalid or expired invitation');
        }

        if (! $invitation->isPending()) {
            throw new Exception($invitation->isExpired() ? 'Invitation has expired' : 'Invitation already processed');
        }

        return DB::transaction(function () use ($invitation, $reason) {
            $invitation->status = 'declined';
            $invitation->declined_at = now();
            $invitation->decline_reason = $reason;
            $invitation->save();

            return true;
        });
    }
}
