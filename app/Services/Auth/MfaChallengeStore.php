<?php

namespace App\Services\Auth;

use App\Models\User;

class MfaChallengeStore
{
    /**
     * Generate cryptographically secure MFA challenge token
     */
    public function create(User $user): string
    {
        // Generate cryptographically secure random token (64 characters)
        $token = bin2hex(random_bytes(32));

        // SECURITY: Encrypt challenge data to protect against cache compromise (OWASP A02:2021)
        cache()->put(
            $this->key($token),
            encrypt([
                'user_id' => $user->id,
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'created_at' => now()->toISOString(),
                'attempts' => 0,
            ]),
            now()->addMinutes(5)
        );

        return $token;
    }

    /**
     * Raw encrypted challenge payload; decrypting it is left to the caller so tampering can be detected there.
     */
    public function get(string $token): mixed
    {
        return cache()->get($this->key($token));
    }

    public function update(string $token, array $challengeData): void
    {
        // SECURITY: Re-encrypt updated challenge data (OWASP A02:2021)
        cache()->put(
            $this->key($token),
            encrypt($challengeData),
            now()->addMinutes(5)
        );
    }

    public function forget(string $token): void
    {
        cache()->forget($this->key($token));
    }

    private function key(string $token): string
    {
        return "mfa_challenge:{$token}";
    }
}
