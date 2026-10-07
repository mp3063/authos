<?php

namespace App\Models\Concerns;

use App\Models\SocialAccount;
use App\Models\User;
use Illuminate\Database\Eloquent\Relations\HasMany;

trait HasSocialLogin
{
    public function socialAccounts(): HasMany
    {
        return $this->hasMany(SocialAccount::class);
    }

    /**
     * Check if user is a social login user
     */
    public function isSocialUser(): bool
    {
        return ! empty($this->provider) && ! empty($this->provider_id);
    }

    /**
     * Check if user has a local password
     */
    public function hasPassword(): bool
    {
        return ! empty($this->password);
    }

    /**
     * Get the social provider display name
     */
    public function getProviderDisplayName(): string
    {
        if (! $this->provider) {
            return 'Local';
        }

        return match ($this->provider) {
            'google' => 'Google',
            'github' => 'GitHub',
            'facebook' => 'Facebook',
            'twitter' => 'Twitter',
            'linkedin' => 'LinkedIn',
            default => ucfirst($this->provider)
        };
    }

    /**
     * Find a user by provider and provider ID
     */
    public static function findBySocialProvider(string $provider, string $providerId): ?User
    {
        return static::where('provider', $provider)
            ->where('provider_id', $providerId)
            ->first();
    }

    /**
     * Create or update a social user
     */
    public static function createOrUpdateFromSocial(
        string $provider,
        string $providerId,
        array $userData,
        ?string $token = null,
        ?string $refreshToken = null
    ): User {
        $user = static::findBySocialProvider($provider, $providerId);

        $attributes = [
            'provider' => $provider,
            'provider_id' => $providerId,
            'name' => $userData['name'],
            'email' => $userData['email'],
            'provider_data' => $userData,
            'email_verified_at' => now(), // Social providers typically verify emails
        ];

        if ($token) {
            $attributes['provider_token'] = $token;
        }

        if ($refreshToken) {
            $attributes['provider_refresh_token'] = $refreshToken;
        }

        if ($user) {
            $user->update($attributes);

            return $user;
        }

        // Create new user
        return static::create($attributes);
    }
}
