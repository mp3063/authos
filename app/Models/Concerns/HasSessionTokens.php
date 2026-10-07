<?php

namespace App\Models\Concerns;

use Illuminate\Support\Str;

trait HasSessionTokens
{
    /**
     * Generate new session token
     */
    public function generateNewSessionToken(): string
    {
        $token = Str::random(64);
        $this->update(['session_token' => $token]);

        return $token;
    }

    /**
     * Generate new refresh token
     */
    public function generateNewRefreshToken(): string
    {
        $token = Str::random(64);
        $this->update(['refresh_token' => $token]);

        return $token;
    }

    /**
     * Find session by session token
     */
    public static function findBySessionToken(string $token): ?self
    {
        return static::where('session_token', $token)->first();
    }
}
