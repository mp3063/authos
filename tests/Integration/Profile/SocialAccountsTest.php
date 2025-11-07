<?php

namespace Tests\Integration\Profile;

use App\Models\SocialAccount;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use Tests\Integration\IntegrationTestCase;

/**
 * Social Accounts Management Integration Tests
 *
 * Tests complete social account management flows including:
 * - Listing connected social accounts
 * - Linking social provider accounts (Google, GitHub, Facebook, etc.)
 * - Unlinking social accounts with safety checks
 * - Social login authentication flow
 * - Duplicate social account prevention
 * - Multiple providers per user support
 * - Legacy social account compatibility
 *
 * @see \App\Http\Controllers\Api\ProfileController::socialAccounts()
 * @see \App\Http\Controllers\Api\SocialAuthController
 */
class SocialAccountsTest extends IntegrationTestCase
{
    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        // Create test user with password
        $this->user = $this->createUser([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_list_connected_social_accounts(): void
    {
        // ARRANGE: User with connected social accounts
        SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google-123',
            'email' => 'test@gmail.com',
            'name' => 'Test User',
            'avatar' => 'https://avatar.example.com/avatar.jpg',
        ]);

        SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'github',
            'provider_id' => 'github-456',
            'email' => 'test@github.com',
            'name' => 'Test User',
        ]);

        // ACT: List social accounts
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/profile/social-accounts');

        // ASSERT: Returns all connected accounts
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'linked_providers' => [
                    '*' => [
                        'id',
                        'provider',
                        'provider_display_name',
                        'provider_id',
                        'email',
                        'name',
                        'avatar',
                        'connected_at',
                        'token_expired',
                    ],
                ],
                'available_providers',
            ],
        ]);

        $data = $response->json('data');
        $this->assertCount(2, $data['linked_providers']);

        // Verify Google account
        $googleAccount = collect($data['linked_providers'])->firstWhere('provider', 'google');
        $this->assertNotNull($googleAccount);
        $this->assertEquals('Google', $googleAccount['provider_display_name']);
        $this->assertEquals('google-123', $googleAccount['provider_id']);

        // Verify GitHub account
        $githubAccount = collect($data['linked_providers'])->firstWhere('provider', 'github');
        $this->assertNotNull($githubAccount);
        $this->assertEquals('GitHub', $githubAccount['provider_display_name']);
        $this->assertEquals('github-456', $githubAccount['provider_id']);

        // Verify available providers structure
        $this->assertArrayHasKey('google', $data['available_providers']);
        $this->assertArrayHasKey('github', $data['available_providers']);
        $this->assertTrue($data['available_providers']['google']['connected']);
        $this->assertTrue($data['available_providers']['github']['connected']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_link_google_account(): void
    {
        // ARRANGE: Mock Google OAuth response
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('google-999');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('user@gmail.com');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('Google User');
        $mockSocialiteUser->shouldReceive('getAvatar')->andReturn('https://avatar.google.com/user.jpg');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn('googleuser');
        $mockSocialiteUser->shouldReceive('getRaw')->andReturn(['sub' => 'google-999']);
        $mockSocialiteUser->token = 'google-access-token';
        $mockSocialiteUser->refreshToken = 'google-refresh-token';
        $mockSocialiteUser->expiresIn = 3600;

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();

        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        // ACT: Link Google account
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/auth/social/link', [
                'provider' => 'google',
                'provider_code' => 'google-oauth-code',
            ]);

        // ASSERT: Account linked successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'provider',
                'provider_id',
                'linked_at',
            ],
            'message',
        ]);

        $data = $response->json('data');
        $this->assertEquals('google', $data['provider']);
        $this->assertEquals('google-999', $data['provider_id']);

        // Verify social account created in database
        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google-999',
            'email' => 'user@gmail.com',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_link_github_account(): void
    {
        // Configure GitHub provider
        config(['services.github.client_id' => 'test-github-id']);
        config(['services.github.client_secret' => 'test-github-secret']);

        // ARRANGE: Mock GitHub OAuth response
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('github-789');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('user@github.com');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('GitHub User');
        $mockSocialiteUser->shouldReceive('getAvatar')->andReturn('https://github.com/avatar.png');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn('githubuser');
        $mockSocialiteUser->shouldReceive('getRaw')->andReturn(['id' => 'github-789']);
        $mockSocialiteUser->token = 'github-access-token';
        $mockSocialiteUser->refreshToken = null;
        $mockSocialiteUser->expiresIn = null;

        Socialite::shouldReceive('driver')
            ->with('github')
            ->andReturnSelf();

        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        // ACT: Link GitHub account
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/auth/social/link', [
                'provider' => 'github',
                'provider_code' => 'github-oauth-code',
            ]);

        // ASSERT: Account linked successfully
        $response->assertOk();
        $this->assertEquals('github', $response->json('data.provider'));

        // Verify in database
        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $this->user->id,
            'provider' => 'github',
            'provider_id' => 'github-789',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_link_facebook_account(): void
    {
        // Configure Facebook provider
        config(['services.facebook.client_id' => 'test-facebook-id']);
        config(['services.facebook.client_secret' => 'test-facebook-secret']);

        // ARRANGE: Mock Facebook OAuth response
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('facebook-555');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('user@facebook.com');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('Facebook User');
        $mockSocialiteUser->shouldReceive('getAvatar')->andReturn('https://facebook.com/avatar.jpg');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn('facebookuser');
        $mockSocialiteUser->shouldReceive('getRaw')->andReturn(['id' => 'facebook-555']);
        $mockSocialiteUser->token = 'facebook-access-token';
        $mockSocialiteUser->refreshToken = null;
        $mockSocialiteUser->expiresIn = 5184000; // 60 days

        Socialite::shouldReceive('driver')
            ->with('facebook')
            ->andReturnSelf();

        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        // ACT: Link Facebook account
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/auth/social/link', [
                'provider' => 'facebook',
                'provider_code' => 'facebook-oauth-code',
            ]);

        // ASSERT: Account linked successfully
        $response->assertOk();
        $this->assertEquals('facebook', $response->json('data.provider'));

        // Verify in database
        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $this->user->id,
            'provider' => 'facebook',
            'provider_id' => 'facebook-555',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_unlink_social_account(): void
    {
        // ARRANGE: User with password and linked social account
        $this->assertTrue($this->user->hasPassword());

        $socialAccount = SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google-123',
        ]);

        // ACT: Unlink social account
        $response = $this->actingAs($this->user, 'api')
            ->deleteJson("/api/v1/profile/social-accounts/{$socialAccount->provider}");

        // ASSERT: Account unlinked successfully
        $response->assertOk();
        $response->assertJson([
            'success' => true,
            'message' => 'Social account unlinked successfully',
        ]);

        // Verify removed from database
        $this->assertDatabaseMissing('social_accounts', [
            'id' => $socialAccount->id,
            'user_id' => $this->user->id,
            'provider' => 'google',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cannot_unlink_social_account_without_password(): void
    {
        // ARRANGE: User without password (social-only login)
        $socialOnlyUser = $this->createUser([
            'email' => 'social@example.com',
            'password' => null, // No password set
            'provider' => 'google',
            'provider_id' => 'google-social-only',
        ]);

        $this->assertFalse($socialOnlyUser->hasPassword());

        // ACT: Attempt to unlink
        $response = $this->actingAs($socialOnlyUser, 'api')
            ->deleteJson('/api/v1/auth/social/unlink');

        // ASSERT: Request rejected
        $response->assertStatus(400);
        $response->assertJson([
            'success' => false,
            'message' => 'Cannot unlink social account without setting a password first',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function duplicate_social_account_link_prevented(): void
    {
        // ARRANGE: Another user with the same Google account
        $otherUser = $this->createUser([
            'email' => 'other@example.com',
        ]);

        SocialAccount::factory()->create([
            'user_id' => $otherUser->id,
            'provider' => 'google',
            'provider_id' => 'google-duplicate-999',
        ]);

        // Mock Socialite to return the same provider ID
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('google-duplicate-999');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('duplicate@gmail.com');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('Duplicate User');
        $mockSocialiteUser->shouldReceive('getAvatar')->andReturn('https://avatar.google.com/user.jpg');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn('duplicateuser');
        $mockSocialiteUser->shouldReceive('getRaw')->andReturn(['sub' => 'google-duplicate-999']);
        $mockSocialiteUser->token = 'google-token';
        $mockSocialiteUser->refreshToken = null;
        $mockSocialiteUser->expiresIn = 3600;

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();

        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        // ACT: Attempt to link same account to different user
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/auth/social/link', [
                'provider' => 'google',
                'provider_code' => 'google-oauth-code',
            ]);

        // ASSERT: Request should fail (duplicate account)
        $response->assertStatus(400);
        $response->assertJson([
            'success' => false,
        ]);

        // Verify no duplicate created
        $this->assertDatabaseMissing('social_accounts', [
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google-duplicate-999',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_have_multiple_social_providers(): void
    {
        // ARRANGE: Create multiple social accounts for same user
        SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google-123',
        ]);

        SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'github',
            'provider_id' => 'github-456',
        ]);

        SocialAccount::factory()->create([
            'user_id' => $this->user->id,
            'provider' => 'facebook',
            'provider_id' => 'facebook-789',
        ]);

        // ACT: List all social accounts
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/profile/social-accounts');

        // ASSERT: Returns all 3 providers
        $response->assertOk();

        $linkedProviders = $response->json('data.linked_providers');
        $this->assertCount(3, $linkedProviders);

        $providers = collect($linkedProviders)->pluck('provider')->toArray();
        $this->assertContains('google', $providers);
        $this->assertContains('github', $providers);
        $this->assertContains('facebook', $providers);

        // Verify all marked as connected in available_providers
        $availableProviders = $response->json('data.available_providers');
        $this->assertTrue($availableProviders['google']['connected']);
        $this->assertTrue($availableProviders['github']['connected']);
        $this->assertTrue($availableProviders['facebook']['connected']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function social_login_creates_new_user_if_not_exists(): void
    {
        // ARRANGE: Mock Google OAuth response for new user
        $mockSocialiteUser = Mockery::mock(SocialiteUser::class);
        $mockSocialiteUser->shouldReceive('getId')->andReturn('google-new-user');
        $mockSocialiteUser->shouldReceive('getEmail')->andReturn('newuser@gmail.com');
        $mockSocialiteUser->shouldReceive('getName')->andReturn('New Google User');
        $mockSocialiteUser->shouldReceive('getAvatar')->andReturn('https://avatar.google.com/new.jpg');
        $mockSocialiteUser->shouldReceive('getNickname')->andReturn('newgoogleuser');
        $mockSocialiteUser->shouldReceive('getRaw')->andReturn(['sub' => 'google-new-user']);
        $mockSocialiteUser->token = 'google-token';
        $mockSocialiteUser->refreshToken = 'google-refresh';
        $mockSocialiteUser->expiresIn = 3600;

        // Mock the full chain: driver()->stateless()->user()
        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();

        Socialite::shouldReceive('stateless')
            ->andReturnSelf();

        Socialite::shouldReceive('user')
            ->andReturn($mockSocialiteUser);

        // ACT: Social login callback
        $response = $this->getJson('/api/v1/auth/social/google/callback?code=google-oauth-code');

        // ASSERT: New user created and authenticated
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'message',
            'data' => [
                'access_token',
                'refresh_token',
                'expires_in',
                'token_type',
                'user' => [
                    'id',
                    'name',
                    'email',
                    'provider',
                    'is_social_user',
                    'has_password',
                ],
            ],
        ]);

        // Verify user created in database
        $this->assertDatabaseHas('users', [
            'email' => 'newuser@gmail.com',
            'name' => 'New Google User',
        ]);

        // Verify social account created
        $this->assertDatabaseHas('social_accounts', [
            'provider' => 'google',
            'provider_id' => 'google-new-user',
            'email' => 'newuser@gmail.com',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function unsupported_provider_rejected(): void
    {
        // ARRANGE: Unsupported provider

        // ACT: Attempt to link unsupported provider
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/auth/social/link', [
                'provider' => 'unsupported-provider',
                'provider_code' => 'some-code',
            ]);

        // ASSERT: Validation fails (Laravel validation returns 422, but we also check for 400 from controller)
        $this->assertContains($response->status(), [400, 422]);
        if ($response->status() === 422) {
            $response->assertJsonValidationErrors(['provider']);
        } else {
            $response->assertJson([
                'success' => false,
            ]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function legacy_social_account_included_in_list(): void
    {
        // ARRANGE: User with legacy social provider (stored on user table)
        $this->user->update([
            'provider' => 'google',
            'provider_id' => 'google-legacy-123',
        ]);

        // ACT: List social accounts
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/profile/social-accounts');

        // ASSERT: Legacy account included
        $response->assertOk();

        $linkedProviders = $response->json('data.linked_providers');
        $this->assertGreaterThanOrEqual(1, count($linkedProviders));

        $legacyAccount = collect($linkedProviders)->firstWhere('provider', 'google');
        $this->assertNotNull($legacyAccount);
        $this->assertEquals('google-legacy-123', $legacyAccount['provider_id']);
        $this->assertTrue($legacyAccount['legacy'] ?? false);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function unauthorized_user_cannot_access_social_accounts(): void
    {
        // ARRANGE: No authentication

        // ACT: Attempt to list social accounts
        $response = $this->getJson('/api/v1/profile/social-accounts');

        // ASSERT: Unauthorized
        $response->assertUnauthorized();
    }
}
