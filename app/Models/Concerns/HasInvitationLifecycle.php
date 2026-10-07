<?php

namespace App\Models\Concerns;

use App\Models\User;
use Illuminate\Database\Eloquent\Builder;

trait HasInvitationLifecycle
{
    /**
     * Scope: Pending invitations
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '>', now());
    }

    /**
     * Scope: isPending (static callable)
     */
    public function scopeIsPending(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '>', now());
    }

    /**
     * Scope: Expired invitations
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '<=', now());
    }

    /**
     * Scope: Static method for expired invitations (alias for expired scope)
     */
    public function scopeIsExpired(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '<=', now());
    }

    /**
     * Scope: Accepted invitations
     */
    public function scopeAccepted(Builder $query): Builder
    {
        return $query->where('status', 'accepted');
    }

    /**
     * Check if invitation is expired
     */
    public function hasExpired(): bool
    {
        return $this->expires_at < now();
    }

    /**
     * Check if invitation is pending
     */
    public function hasPending(): bool
    {
        return $this->status === 'pending' && ! $this->hasExpired();
    }

    /**
     * Instance method to check if invitation is expired
     */
    public function isExpired(): bool
    {
        return $this->hasExpired();
    }

    /**
     * Instance method to check if invitation is pending
     */
    public function isPending(): bool
    {
        return $this->hasPending();
    }

    /**
     * Check if invitation is accepted
     */
    public function isAccepted(): bool
    {
        return $this->status === 'accepted';
    }

    /**
     * Check if invitation can be accepted
     */
    public function canBeAccepted(): bool
    {
        return $this->status === 'pending' && ! $this->hasExpired();
    }

    /**
     * Accept the invitation
     */
    public function accept(User $user): bool
    {
        if (! $this->canBeAccepted()) {
            return false;
        }

        $this->update([
            'status' => 'accepted',
            'accepted_at' => now(),
            'accepted_by' => $user->id,
        ]);

        return true;
    }

    /**
     * Mark invitation as accepted
     */
    public function markAsAccepted(User|int $user): bool
    {
        if ($user instanceof User) {
            return $this->accept($user);
        }

        $userModel = User::find($user);

        return $userModel && $this->accept($userModel);
    }

    /**
     * Mark invitation as declined
     */
    public function markAsDeclined(?string $reason = null): bool
    {
        if ($this->status !== 'pending') {
            return false;
        }

        $this->update([
            'status' => 'declined',
            'declined_at' => now(),
            'decline_reason' => $reason,
        ]);

        return true;
    }

    /**
     * Mark invitation as cancelled
     */
    public function markAsCancelled(User|int $user): bool
    {
        if ($this->status !== 'pending') {
            return false;
        }

        $userId = $user instanceof User ? $user->id : $user;

        $this->update([
            'status' => 'cancelled',
            'cancelled_at' => now(),
            'cancelled_by' => $userId,
        ]);

        return true;
    }
}
