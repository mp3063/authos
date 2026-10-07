<?php

namespace App\Models\Concerns;

use App\Models\User;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

trait AssignableToUsers
{
    /**
     * The users that have this custom role
     */
    public function users(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'user_custom_roles')
            ->withPivot(['granted_at', 'granted_by'])
            ->withTimestamps();
    }

    /**
     * Assign this role to a user
     */
    public function assignToUser(User|int $user, ?User $grantedBy = null): void
    {
        $userId = $user instanceof User ? $user->id : $user;

        if (! $this->users()->where('user_id', $userId)->exists()) {
            $this->users()->attach($userId, [
                'granted_at' => now(),
                'granted_by' => $grantedBy?->id,
            ]);
        }
    }

    /**
     * Remove this role from a user
     */
    public function unassignFromUser(User|int $user): void
    {
        $userId = $user instanceof User ? $user->id : $user;
        $this->users()->detach($userId);
    }

    /**
     * Get the count of users assigned to this role
     */
    public function getUserCount(): int
    {
        return $this->users()->count();
    }
}
