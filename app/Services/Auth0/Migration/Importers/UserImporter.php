<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration\Importers;

use App\Models\Organization;
use App\Models\SocialAccount;
use App\Models\User;
use App\Services\Auth0\DTOs\Auth0UserDTO;
use App\Services\Auth0\Migration\ImportResult;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PragmaRX\Google2FA\Google2FA;

class UserImporter
{
    public const STRATEGY_RESET = 'reset';

    public const STRATEGY_LAZY = 'lazy';

    public const STRATEGY_HASH = 'hash';

    public function __construct(
        private string $passwordStrategy = self::STRATEGY_LAZY,
        private ?Organization $defaultOrganization = null,
    ) {}

    /**
     * Import users from Auth0
     *
     * @param  array<int, Auth0UserDTO>  $auth0Users
     */
    public function import(array $auth0Users, bool $dryRun = false): ImportResult
    {
        $result = new ImportResult;

        foreach ($auth0Users as $auth0User) {
            try {
                // Skip users without email
                if (empty($auth0User->email)) {
                    $result->addSkipped("User {$auth0User->userId} has no email");

                    continue;
                }

                // Check if user already exists
                if (User::where('email', $auth0User->email)->exists()) {
                    $result->addSkipped("User with email {$auth0User->email} already exists");

                    continue;
                }

                if ($dryRun) {
                    $result->addSuccess($auth0User, null);

                    continue;
                }

                // Import user
                $user = $this->importUser($auth0User);

                $result->addSuccess($auth0User, $user->id);
            } catch (\Throwable $e) {
                $result->addFailure($auth0User, $e);
            }
        }

        return $result;
    }

    /**
     * Import a single user
     */
    private function importUser(Auth0UserDTO $auth0User): User
    {
        return DB::transaction(function () use ($auth0User) {
            // Create user
            $user = User::create([
                'name' => $auth0User->name,
                'email' => $auth0User->email,
                'password' => $this->handlePassword($auth0User),
                'email_verified_at' => $auth0User->emailVerified ? now() : null,
                'avatar' => $auth0User->picture,
                'organization_id' => $this->getOrganizationId(),
            ]);

            // Store Auth0 user ID in metadata for reference
            $user->update([
                'metadata' => array_merge(
                    $user->metadata ?? [],
                    [
                        'auth0_user_id' => $auth0User->userId,
                        'imported_from_auth0' => true,
                        'imported_at' => now()->toIso8601String(),
                    ]
                ),
            ]);

            // Handle password reset if needed
            if ($this->passwordStrategy === self::STRATEGY_RESET) {
                $this->markForPasswordReset($user);
            }

            // Handle lazy migration if needed
            if ($this->passwordStrategy === self::STRATEGY_LAZY) {
                $this->markForLazyMigration($user, $auth0User);
            }

            // Import social accounts
            if (! empty($auth0User->getSocialConnections())) {
                $this->importSocialAccounts($user, $auth0User->getSocialConnections());
            }

            // Enable MFA if user had it in Auth0
            if ($auth0User->hasMFA()) {
                $this->enableMFA($user);
            }

            // Import user metadata
            $this->importMetadata($user, $auth0User);

            return $user;
        });
    }

    /**
     * Handle password based on strategy
     */
    private function handlePassword(Auth0UserDTO $auth0User): string
    {
        return match ($this->passwordStrategy) {
            self::STRATEGY_RESET => $this->generateTemporaryPassword(),
            self::STRATEGY_LAZY => $this->generateTemporaryPassword(),
            self::STRATEGY_HASH => $this->importPasswordHash($auth0User),
            default => $this->generateTemporaryPassword(),
        };
    }

    /**
     * Generate temporary password
     */
    private function generateTemporaryPassword(): string
    {
        return Hash::make(Str::random(32));
    }

    /**
     * Import password hash (if available)
     */
    private function importPasswordHash(Auth0UserDTO $auth0User): string
    {
        // Auth0 typically doesn't expose password hashes
        // This would only work if you have direct database access
        // For now, fall back to temporary password
        return $this->generateTemporaryPassword();
    }

    /**
     * Mark user for password reset
     */
    private function markForPasswordReset(User $user): void
    {
        $user->update([
            'metadata' => array_merge(
                $user->metadata ?? [],
                [
                    'requires_password_reset' => true,
                    'password_reset_reason' => 'Migrated from Auth0',
                ]
            ),
        ]);

        // TODO: Send password reset email
        // This should trigger a password reset email to the user
    }

    /**
     * Mark user for lazy migration
     */
    private function markForLazyMigration(User $user, Auth0UserDTO $auth0User): void
    {
        $user->update([
            'metadata' => array_merge(
                $user->metadata ?? [],
                [
                    'lazy_migration_enabled' => true,
                    'auth0_user_id' => $auth0User->userId,
                ]
            ),
        ]);
    }

    /**
     * Import social accounts
     *
     * @param  array<int, array{provider: string, userId: string, connection: string, isSocial: bool}>  $socialConnections
     */
    private function importSocialAccounts(User $user, array $socialConnections): void
    {
        foreach ($socialConnections as $connection) {
            // Map Auth0 provider to our provider names
            $provider = $this->mapProvider($connection['provider']);

            // Check if social account already exists
            $exists = SocialAccount::where('user_id', $user->id)
                ->where('provider', $provider)
                ->where('provider_id', $connection['userId'])
                ->exists();

            if ($exists) {
                continue;
            }

            SocialAccount::create([
                'user_id' => $user->id,
                'provider' => $provider,
                'provider_id' => $connection['userId'],
            ]);
        }
    }

    /**
     * Map Auth0 provider names to our provider names
     */
    private function mapProvider(string $auth0Provider): string
    {
        return match (strtolower($auth0Provider)) {
            'google-oauth2' => 'google',
            'github' => 'github',
            'facebook' => 'facebook',
            'twitter' => 'twitter',
            'linkedin' => 'linkedin',
            default => $auth0Provider,
        };
    }

    /**
     * Enable MFA for user
     */
    private function enableMFA(User $user): void
    {
        try {
            $google2fa = new Google2FA;
            $secret = $google2fa->generateSecretKey();

            $user->update([
                'mfa_enabled' => true,
                'mfa_secret' => encrypt($secret),
                'metadata' => array_merge(
                    $user->metadata ?? [],
                    [
                        'mfa_migrated_from_auth0' => true,
                        'mfa_requires_setup' => true, // User needs to reconfigure MFA
                    ]
                ),
            ]);

            // Generate recovery codes
            $recoveryCodes = collect(range(1, 8))
                ->map(fn () => Str::upper(Str::random(8)))
                ->toArray();

            $user->update([
                'mfa_recovery_codes' => encrypt(json_encode($recoveryCodes)),
            ]);
        } catch (\Throwable $e) {
            // Log error but don't fail the import
            logger()->error('Failed to enable MFA for imported user', [
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Import user metadata
     */
    private function importMetadata(User $user, Auth0UserDTO $auth0User): void
    {
        $metadata = array_merge(
            $user->metadata ?? [],
            [
                'auth0_app_metadata' => $auth0User->appMetadata,
                'auth0_user_metadata' => $auth0User->userMetadata,
                'auth0_logins_count' => $auth0User->loginsCount,
                'auth0_last_login' => $auth0User->lastLogin?->format('Y-m-d H:i:s'),
                'auth0_created_at' => $auth0User->createdAt?->format('Y-m-d H:i:s'),
            ]
        );

        $user->update(['metadata' => $metadata]);
    }

    /**
     * Get organization ID for imported users
     */
    private function getOrganizationId(): ?int
    {
        return $this->defaultOrganization?->id;
    }

    /**
     * Set default organization for imported users
     */
    public function setDefaultOrganization(Organization $organization): void
    {
        $this->defaultOrganization = $organization;
    }

    /**
     * Set password strategy
     */
    public function setPasswordStrategy(string $strategy): void
    {
        if (! in_array($strategy, [self::STRATEGY_RESET, self::STRATEGY_LAZY, self::STRATEGY_HASH], true)) {
            throw new \InvalidArgumentException("Invalid password strategy: {$strategy}");
        }

        $this->passwordStrategy = $strategy;
    }
}
