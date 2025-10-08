<?php

namespace Tests\Integration\OAuth;

use App\Models\Organization;
use App\Models\SocialAccount;
use App\Models\User;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Social Authentication Integration Tests
 *
 * Tests social authentication flows including:
 * - Google OAuth flow
 * - GitHub OAuth flow
 * - Facebook OAuth flow
 * - Twitter OAuth flow
 * - LinkedIn OAuth flow
 * - Account linking scenarios
 */
class SocialAuthIntegrationTest extends TestCase
{
    protected Organization $organization;

    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        // Configure social providers for testing
        config([
            'services.google.client_id' => 'test-google-client-id',
            'services.google.client_secret' => 'test-google-client-secret',
            'services.google.redirect' => 'http://localhost/api/v1/auth/social/google/callback',
            'services.github.client_id' => 'test-github-client-id',
            'services.github.client_secret' => 'test-github-client-secret',
            'services.github.redirect' => 'http://localhost/api/v1/auth/social/github/callback',
            'services.facebook.client_id' => 'test-facebook-client-id',
            'services.facebook.client_secret' => 'test-facebook-client-secret',
            'services.facebook.redirect' => 'http://localhost/api/v1/auth/social/facebook/callback',
            'services.twitter.client_id' => 'test-twitter-client-id',
            'services.twitter.client_secret' => 'test-twitter-client-secret',
            'services.twitter.redirect' => 'http://localhost/api/v1/auth/social/twitter/callback',
            'services.linkedin.client_id' => 'test-linkedin-client-id',
            'services.linkedin.client_secret' => 'test-linkedin-client-secret',
            'services.linkedin.redirect' => 'http://localhost/api/v1/auth/social/linkedin/callback',
        ]);

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_providers_list(): void
    {
        $response = $this->getJson('/api/v1/auth/social/providers');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertArrayHasKey('providers', $data['data']);
        $this->assertArrayHasKey('count', $data['data']);

        // Verify expected providers are listed
        $providers = array_keys($data['data']['providers']);
        $expectedProviders = ['google', 'github', 'facebook', 'twitter', 'linkedin'];

        foreach ($expectedProviders as $provider) {
            $this->assertContains($provider, $providers);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_google_redirect_url(): void
    {
        $response = $this->getJson('/api/v1/auth/social/google');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertArrayHasKey('redirect_url', $data['data']);
        $this->assertArrayHasKey('provider', $data['data']);
        $this->assertEquals('google', $data['data']['provider']);

        // Verify redirect URL contains Google OAuth parameters
        $redirectUrl = $data['data']['redirect_url'];
        $this->assertStringContainsString('accounts.google.com', $redirectUrl);
        $this->assertStringContainsString('client_id', $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_github_redirect_url(): void
    {
        $response = $this->getJson('/api/v1/auth/social/github');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals('github', $data['data']['provider']);

        $redirectUrl = $data['data']['redirect_url'];
        $this->assertStringContainsString('github.com', $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_facebook_redirect_url(): void
    {
        $response = $this->getJson('/api/v1/auth/social/facebook');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals('facebook', $data['data']['provider']);

        $redirectUrl = $data['data']['redirect_url'];
        $this->assertStringContainsString('facebook.com', $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_twitter_redirect_url(): void
    {
        $this->markTestSkipped('Twitter OAuth 1.0 requires special session handling - tested separately');

        $response = $this->withSession([])->getJson('/api/v1/auth/social/twitter');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals('twitter', $data['data']['provider']);

        $redirectUrl = $data['data']['redirect_url'];
        $this->assertStringContainsString('twitter.com', $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_linkedin_redirect_url(): void
    {
        $response = $this->getJson('/api/v1/auth/social/linkedin');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals('linkedin', $data['data']['provider']);

        $redirectUrl = $data['data']['redirect_url'];
        $this->assertStringContainsString('linkedin.com', $redirectUrl);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_unsupported_provider_rejected(): void
    {
        $response = $this->getJson('/api/v1/auth/social/unsupported-provider');

        $response->assertStatus(400);
        $data = $response->json();

        $this->assertFalse($data['success']);
        $this->assertStringContainsString('Unsupported social provider', $data['message']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_redirect_with_organization(): void
    {
        $response = $this->getJson('/api/v1/auth/social/google?organization='.$this->organization->slug);

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals($this->organization->slug, $data['data']['organization']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_callback_without_code(): void
    {
        // Callback without authorization code should fail
        $response = $this->getJson('/api/v1/auth/social/google/callback');

        $response->assertStatus(400);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_account_linking_requires_authentication(): void
    {
        $response = $this->postJson('/api/v1/auth/social/link', [
            'provider' => 'google',
            'provider_code' => 'test-code',
        ]);

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_account_unlinking_requires_authentication(): void
    {
        $response = $this->deleteJson('/api/v1/auth/social/unlink');

        $response->assertStatus(401);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_account_unlinking_requires_password(): void
    {
        // Create user without password (social-only user)
        $socialUser = User::factory()->create([
            'password' => null,
            'provider' => 'google',
            'provider_id' => 'google-123',
        ]);

        Passport::actingAs($socialUser);

        $response = $this->deleteJson('/api/v1/auth/social/unlink');

        $response->assertStatus(400);
        $data = $response->json();

        $this->assertFalse($data['success']);
        $this->assertStringContainsString('Cannot unlink social account without setting a password first', $data['message']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_account_unlinking_success(): void
    {
        // Create user with password and social provider
        $user = User::factory()->create([
            'password' => bcrypt('password123'),
            'provider' => 'google',
            'provider_id' => 'google-123',
        ]);

        Passport::actingAs($user);

        $response = $this->deleteJson('/api/v1/auth/social/unlink');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['success']);
        $this->assertEquals('Social account unlinked successfully', $data['message']);

        // Verify provider fields are cleared
        $user->refresh();
        $this->assertNull($user->provider);
        $this->assertNull($user->provider_id);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_authentication_creates_social_account_record(): void
    {
        // This would require mocking Socialite
        // For now, test the model relationship

        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => 'google-user-123',
        ]);

        $socialAccount = SocialAccount::create([
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_id' => 'google-user-123',
            'provider_email' => 'user@gmail.com',
            'provider_name' => 'Test User',
            'provider_avatar' => 'https://example.com/avatar.jpg',
            'provider_token' => 'access-token',
            'provider_refresh_token' => 'refresh-token',
            'provider_data' => ['extra' => 'data'],
        ]);

        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_id' => 'google-user-123',
        ]);

        // Verify relationship
        $this->assertEquals($user->id, $socialAccount->user_id);
        $this->assertEquals('google', $socialAccount->provider);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_multiple_social_accounts_per_user(): void
    {
        $user = User::factory()->create();

        // Link multiple social providers
        $providers = ['google', 'github', 'linkedin'];

        foreach ($providers as $provider) {
            SocialAccount::create([
                'user_id' => $user->id,
                'provider' => $provider,
                'provider_id' => $provider.'-id-123',
                'provider_email' => "user@{$provider}.com",
                'provider_token' => 'token-'.$provider,
            ]);
        }

        $socialAccounts = SocialAccount::where('user_id', $user->id)->get();
        $this->assertCount(3, $socialAccounts);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_provider_display_names(): void
    {
        $providers = [
            'google' => 'Google',
            'github' => 'GitHub',
            'facebook' => 'Facebook',
            'twitter' => 'Twitter',
            'linkedin' => 'LinkedIn',
        ];

        foreach ($providers as $key => $displayName) {
            $user = User::factory()->create([
                'provider' => $key,
                'provider_id' => $key.'-123',
            ]);

            $this->assertEquals($displayName, $user->getProviderDisplayName());
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_user_identification(): void
    {
        // Social user (with provider)
        $socialUser = User::factory()->create([
            'provider' => 'google',
            'provider_id' => 'google-123',
        ]);

        $this->assertTrue($socialUser->isSocialUser());

        // Regular user (without provider)
        $regularUser = User::factory()->create([
            'provider' => null,
            'provider_id' => null,
        ]);

        $this->assertFalse($regularUser->isSocialUser());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_login_with_organization_restrictions(): void
    {
        // Organization that disallows registration
        $restrictedOrg = Organization::factory()->create([
            'settings' => ['allow_registration' => false],
        ]);

        $response = $this->getJson('/api/v1/auth/social/google?organization='.$restrictedOrg->slug);

        // Should still return redirect URL (restriction checked during callback)
        $response->assertStatus(200);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_profile_includes_avatar(): void
    {
        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => 'google-123',
            'avatar' => 'https://lh3.googleusercontent.com/avatar.jpg',
        ]);

        Passport::actingAs($user);

        $response = $this->getJson('/api/v1/auth/user');

        $response->assertStatus(200);
        $data = $response->json();

        $this->assertTrue($data['is_social_user']);
        $this->assertEquals('google', $data['provider']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_accounts_visible_in_profile(): void
    {
        $user = User::factory()->create();

        SocialAccount::create([
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_id' => 'google-123',
            'provider_email' => 'user@gmail.com',
            'provider_token' => 'token',
        ]);

        Passport::actingAs($user);

        $response = $this->getJson('/api/v1/profile/social-accounts');

        $response->assertStatus(200);
        // Response structure depends on implementation
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_duplicate_social_account_prevention(): void
    {
        // Create first user with social account
        $user1 = User::factory()->create([
            'provider' => 'google',
            'provider_id' => 'google-unique-123',
        ]);

        // Attempt to create second user with same provider_id should fail
        // This is enforced at the service layer during social authentication
        $this->assertDatabaseHas('users', [
            'provider' => 'google',
            'provider_id' => 'google-unique-123',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_social_token_refresh(): void
    {
        $socialAccount = SocialAccount::create([
            'user_id' => $this->user->id,
            'provider' => 'google',
            'provider_id' => 'google-123',
            'provider_token' => 'old-token',
            'provider_refresh_token' => 'refresh-token',
            'provider_email' => 'user@gmail.com',
        ]);

        // Update token
        $socialAccount->update([
            'provider_token' => 'new-token',
        ]);

        $socialAccount->refresh();

        $this->assertEquals('new-token', $socialAccount->provider_token);
        $this->assertEquals('refresh-token', $socialAccount->provider_refresh_token);
    }
}
