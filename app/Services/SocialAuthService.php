<?php

namespace App\Services;

use App\Models\User;
use App\Models\Organization;
use App\Models\AuthenticationLog;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Spatie\Permission\Models\Role;

class SocialAuthService
{
    public function __construct(
        private OAuthService $oauthService
    ) {}

    /**
     * Get the redirect URL for the given provider
     */
    public function getRedirectUrl(string $provider): string
    {
        return Socialite::driver($provider)
            ->stateless()
            ->redirect()
            ->getTargetUrl();
    }

    /**
     * Handle the OAuth callback and authenticate the user
     */
    public function handleCallback(string $provider, ?string $organizationSlug = null): array
    {
        try {
            $socialUser = Socialite::driver($provider)->stateless()->user();
            
            return DB::transaction(function () use ($provider, $socialUser, $organizationSlug) {
                // Find or create the user
                $user = $this->findOrCreateUser($provider, $socialUser, $organizationSlug);
                
                // Generate tokens using OAuth service
                $tokens = $this->oauthService->generateAccessToken($user, [
                    'openid', 'profile', 'email'
                ]);
                
                // Log the authentication
                $this->logAuthentication($user, $provider, true);
                
                return [
                    'user' => $user,
                    'access_token' => $tokens->access_token ?? $tokens->accessToken ?? null,
                    'refresh_token' => $tokens->refresh_token ?? $tokens->refreshToken ?? null,
                    'expires_in' => $tokens->expires_in ?? $tokens->expiresIn ?? 3600,
                    'token_type' => 'Bearer',
                ];
            });
        } catch (\Exception $e) {
            Log::error('Social authentication failed', [
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            throw new \Exception('Social authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Find or create user from social provider data
     */
    private function findOrCreateUser(string $provider, SocialiteUser $socialUser, ?string $organizationSlug = null): User
    {
        // First, try to find user by provider and provider ID
        $user = User::findBySocialProvider($provider, $socialUser->getId());
        
        if ($user) {
            // Update existing social user data
            $user = $this->updateUserFromSocial($user, $socialUser);
            return $user;
        }
        
        // Check if user exists with same email (account linking)
        $existingUser = User::where('email', $socialUser->getEmail())->first();
        
        if ($existingUser) {
            // Link social account to existing user
            return $this->linkSocialAccount($existingUser, $provider, $socialUser);
        }
        
        // Create new user
        return $this->createUserFromSocial($provider, $socialUser, $organizationSlug);
    }

    /**
     * Create a new user from social provider data
     */
    private function createUserFromSocial(string $provider, SocialiteUser $socialUser, ?string $organizationSlug = null): User
    {
        // Determine organization
        $organization = null;
        if ($organizationSlug) {
            $organization = Organization::where('slug', $organizationSlug)->first();
            if (!$organization) {
                throw new \Exception('Organization not found');
            }
            
            // Check if organization allows registration
            $settings = $organization->settings ?? [];
            if (isset($settings['allow_registration']) && !$settings['allow_registration']) {
                throw new \Exception('Organization does not allow registration');
            }
        } else {
            // Use default organization or create one
            $organization = Organization::where('is_active', true)->first();
        }

        $userData = [
            'name' => $socialUser->getName(),
            'email' => $socialUser->getEmail(),
            'avatar' => $socialUser->getAvatar(),
            'organization_id' => $organization?->id,
            'provider' => $provider,
            'provider_id' => $socialUser->getId(),
            'provider_token' => $socialUser->token,
            'provider_refresh_token' => $socialUser->refreshToken,
            'provider_data' => [
                'name' => $socialUser->getName(),
                'email' => $socialUser->getEmail(),
                'avatar' => $socialUser->getAvatar(),
                'nickname' => $socialUser->getNickname(),
                'raw' => $socialUser->getRaw(),
            ],
            'email_verified_at' => now(),
            'is_active' => true,
        ];

        $user = User::create($userData);
        
        // Assign default role
        $this->assignDefaultRole($user, $organization);
        
        return $user;
    }

    /**
     * Update existing user with fresh social data
     */
    private function updateUserFromSocial(User $user, SocialiteUser $socialUser): User
    {
        $user->update([
            'name' => $socialUser->getName(),
            'avatar' => $socialUser->getAvatar(),
            'provider_token' => $socialUser->token,
            'provider_refresh_token' => $socialUser->refreshToken,
            'provider_data' => [
                'name' => $socialUser->getName(),
                'email' => $socialUser->getEmail(),
                'avatar' => $socialUser->getAvatar(),
                'nickname' => $socialUser->getNickname(),
                'raw' => $socialUser->getRaw(),
            ],
        ]);
        
        return $user;
    }

    /**
     * Link social account to existing user
     */
    private function linkSocialAccount(User $user, string $provider, SocialiteUser $socialUser): User
    {
        // Update user with social provider information
        $user->update([
            'provider' => $provider,
            'provider_id' => $socialUser->getId(),
            'provider_token' => $socialUser->token,
            'provider_refresh_token' => $socialUser->refreshToken,
            'provider_data' => [
                'name' => $socialUser->getName(),
                'email' => $socialUser->getEmail(),
                'avatar' => $socialUser->getAvatar(),
                'nickname' => $socialUser->getNickname(),
                'raw' => $socialUser->getRaw(),
            ],
            'avatar' => $socialUser->getAvatar() ?: $user->avatar,
        ]);
        
        return $user;
    }

    /**
     * Assign default role to new social user
     */
    private function assignDefaultRole(User $user, ?Organization $organization): void
    {
        try {
            if ($organization) {
                // Set organization context for permission assignment
                $user->setPermissionsTeamId($organization->id);
                
                // Try to assign organization-specific 'user' role
                $orgRole = Role::where('name', 'user')
                    ->where('organization_id', $organization->id)
                    ->first();
                    
                if ($orgRole) {
                    $user->assignRole($orgRole);
                } else {
                    // Fallback to global 'user' role
                    $globalRole = Role::where('name', 'user')
                        ->whereNull('organization_id')
                        ->first();
                        
                    if ($globalRole) {
                        $user->assignRole($globalRole);
                    }
                }
            } else {
                // Assign global 'user' role
                $globalRole = Role::where('name', 'user')
                    ->whereNull('organization_id')
                    ->first();
                    
                if ($globalRole) {
                    $user->assignRole($globalRole);
                }
            }
        } catch (\Exception $e) {
            Log::warning('Failed to assign default role to social user', [
                'user_id' => $user->id,
                'organization_id' => $organization?->id,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Log authentication event
     */
    private function logAuthentication(User $user, string $provider, bool $success): void
    {
        try {
            AuthenticationLog::create([
                'user_id' => $user->id,
                'event' => $success ? 'social_login_success' : 'social_login_failed',
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                'metadata' => [
                    'provider' => $provider,
                    'provider_display_name' => $user->getProviderDisplayName(),
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to log social authentication event', [
                'user_id' => $user->id,
                'provider' => $provider,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Get available social providers
     */
    public function getAvailableProviders(): array
    {
        return [
            'google' => [
                'name' => 'Google',
                'enabled' => !empty(config('services.google.client_id')),
                'icon' => 'fab fa-google',
                'color' => '#db4437',
            ],
            'github' => [
                'name' => 'GitHub', 
                'enabled' => !empty(config('services.github.client_id')),
                'icon' => 'fab fa-github',
                'color' => '#333',
            ],
            'facebook' => [
                'name' => 'Facebook',
                'enabled' => !empty(config('services.facebook.client_id')),
                'icon' => 'fab fa-facebook-f',
                'color' => '#3b5998',
            ],
            'twitter' => [
                'name' => 'Twitter',
                'enabled' => !empty(config('services.twitter.client_id')),
                'icon' => 'fab fa-twitter',
                'color' => '#1da1f2',
            ],
            'linkedin' => [
                'name' => 'LinkedIn',
                'enabled' => !empty(config('services.linkedin.client_id')),
                'icon' => 'fab fa-linkedin-in',
                'color' => '#0077b5',
            ],
        ];
    }

    /**
     * Check if provider is supported
     */
    public function isProviderSupported(string $provider): bool
    {
        $availableProviders = array_keys($this->getAvailableProviders());
        return in_array($provider, $availableProviders);
    }

    /**
     * Check if provider is configured and enabled
     */
    public function isProviderEnabled(string $provider): bool
    {
        $providers = $this->getAvailableProviders();
        return isset($providers[$provider]) && $providers[$provider]['enabled'];
    }
}