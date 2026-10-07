<?php

namespace App\Models\Concerns;

use Illuminate\Support\Str;

trait HasInvitationToken
{
    /**
     * Generate a new token
     */
    public function generateNewToken(): string
    {
        $token = Str::random(64);
        $this->update(['token' => $token]);

        return $token;
    }

    /**
     * Regenerate token and extend expiry
     */
    public function regenerateToken(int $days = 7): string
    {
        $token = Str::random(32); // Use 32 chars as expected by tests
        $this->update([
            'token' => $token,
            'expires_at' => now()->addDays($days),
        ]);

        return $token;
    }

    /**
     * Extend invitation expiry
     */
    public function extend(int $days = 7): void
    {
        $this->update([
            'expires_at' => now()->addDays($days),
        ]);
    }

    /**
     * Get invitation URL
     */
    public function getInvitationUrl(): string
    {
        return url("/invitations/accept/$this->token");
    }

    /**
     * Get days until expiry
     */
    public function daysUntilExpiry(): int
    {
        return (int) ceil(now()->diffInDays($this->expires_at));
    }

    /**
     * Find invitation by token
     */
    public static function findByToken(string $token): ?self
    {
        return static::where('token', $token)->first();
    }
}
