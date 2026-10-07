<?php

namespace App\Models\Concerns;

use App\Models\User;

trait HasSessionLifecycle
{
    /**
     * Check if session is expired
     */
    public function isExpired(): bool
    {
        return $this->expires_at < now();
    }

    /**
     * Check if session is active
     */
    public function isActive(): bool
    {
        return ! $this->isExpired() && is_null($this->logged_out_at);
    }

    /**
     * Extend session expiry
     */
    public function extendSession(int $seconds = 3600): void
    {
        $newExpiry = $this->expires_at->copy()->addSeconds($seconds);

        $this->update([
            'expires_at' => $newExpiry,
            'last_activity_at' => now(),
        ]);

        $this->refresh();
    }

    /**
     * Update last activity timestamp
     */
    public function updateLastActivity(): void
    {
        $this->update(['last_activity_at' => now()]);
    }

    /**
     * Logout the session
     */
    public function logout(User|int|null $user = null): bool
    {
        $userId = $user instanceof User ? $user->id : $user;

        return $this->update([
            'logged_out_at' => now(),
            'logged_out_by' => $userId,
        ]);
    }

    /**
     * Get minutes since last activity
     */
    public function minutesSinceLastActivity(): int
    {
        return (int) abs(now()->diffInMinutes($this->last_activity_at));
    }

    /**
     * Get hours until expiry
     */
    public function hoursUntilExpiry(): int
    {
        if ($this->isExpired()) {
            return 0;
        }

        return (int) round(now()->diffInHours($this->expires_at));
    }

    /**
     * Legacy method aliases for backward compatibility
     */
    public function updateActivity(): void
    {
        $this->updateLastActivity();
    }

    public function extend(?int $seconds = null): void
    {
        $this->extendSession($seconds ?? 3600);
    }

    public function revoke(): bool
    {
        return $this->logout();
    }
}
