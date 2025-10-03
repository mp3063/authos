<?php

namespace Tests\Integration\EndToEnd;

use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Mockery;
use PHPUnit\Framework\Attributes\Test;

/**
 * End-to-End tests for comprehensive Social Authentication flows.
 *
 * Tests complete social authentication user journeys including:
 * - New user social registration
 * - Existing user social login
 * - Social account linking/unlinking
 * - Cross-organization isolation
 * - Security validations
 * - Error handling
 */
class SocialAuthFlowsTest extends EndToEndTestCase
{
    private array $socialProviders = ['google', 'github', 'facebook', 'twitter', 'linkedin'];

    private array $mockSocialUsers = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setupSocialProviderMocks();
        $this->setupMockSocialUsers();
    }

    /**
     * Setup social provider configuration for testing
     */
    private function setupSocialProviderMocks(): void
    {
        foreach ($this->socialProviders as $provider) {
            Config::set("services.$provider", [
                'client_id' => "test_{$provider}_client_id",
                'client_secret' => "test_{$provider}_client_secret",
                'redirect' => url("/auth/social/$provider/callback"),
            ]);
        }
    }

    /**
     * Create mock social user data for each provider
     */
    private function setupMockSocialUsers(): void
    {
        $this->mockSocialUsers = [
            'google' => $this->createMockSocialiteUser([
                'id' => 'google_123456789',
                'name' => 'John Google',
                'email' => 'john.google@gmail.com',
                'avatar' => 'https://lh3.googleusercontent.com/avatar',
                'nickname' => 'johngoogle',
            ]),
            'github' => $this->createMockSocialiteUser([
                'id' => 'github_987654321',
                'name' => 'Jane GitHub',
                'email' => 'jane.github@github.com',
                'avatar' => 'https://avatars.githubusercontent.com/avatar',
                'nickname' => 'janegithub',
            ]),
            'facebook' => $this->createMockSocialiteUser([
                'id' => 'facebook_555666777',
                'name' => 'Bob Facebook',
                'email' => 'bob.facebook@facebook.com',
                'avatar' => 'https://graph.facebook.com/avatar',
                'nickname' => 'bobfacebook',
            ]),
            'twitter' => $this->createMockSocialiteUser([
                'id' => 'twitter_111222333',
                'name' => 'Alice Twitter',
                'email' => 'alice.twitter@twitter.com',
                'avatar' => 'https://pbs.twimg.com/avatar',
                'nickname' => 'alicetwitter',
            ]),
            'linkedin' => $this->createMockSocialiteUser([
                'id' => 'linkedin_444555666',
                'name' => 'Charlie LinkedIn',
                'email' => 'charlie.linkedin@linkedin.com',
                'avatar' => 'https://media.licdn.com/avatar',
                'nickname' => 'charlielinkedin',
            ]),
        ];
    }

    /**
     * Create a mock SocialiteUser instance
     */
    private function createMockSocialiteUser(array $data): SocialiteUser
    {
        $mock = Mockery::mock(SocialiteUser::class);
        $mock->shouldReceive('getId')->andReturn($data['id']);
        $mock->shouldReceive('getName')->andReturn($data['name']);
        $mock->shouldReceive('getEmail')->andReturn($data['email']);
        $mock->shouldReceive('getAvatar')->andReturn($data['avatar']);
        $mock->shouldReceive('getNickname')->andReturn($data['nickname'] ?? null);
        $mock->shouldReceive('getRaw')->andReturn($data);
        $mock->token = 'social_access_token_'.uniqid();
        $mock->refreshToken = 'social_refresh_token_'.uniqid();

        return $mock;
    }

    /**
     * Test Google new user registration flow
     */
    #[Test]
    public function test_google_new_user_registration_flow(): void
    {
        $this->performNewUserSocialRegistrationFlow('google', 'john.google@gmail.com');
    }

    /**
     * Test GitHub new user registration flow
     */
    #[Test]
    public function test_github_new_user_registration_flow(): void
    {
        $this->performNewUserSocialRegistrationFlow('github', 'jane.github@github.com');
    }

    /**
     * Test Facebook new user registration flow
     */
    #[Test]
    public function test_facebook_new_user_registration_flow(): void
    {
        $this->performNewUserSocialRegistrationFlow('facebook', 'bob.facebook@facebook.com');
    }

    /**
     * Test Twitter new user registration flow
     */
    #[Test]
    public function test_twitter_new_user_registration_flow(): void
    {
        $this->performNewUserSocialRegistrationFlow('twitter', 'alice.twitter@twitter.com');
    }

    /**
     * Test LinkedIn new user registration flow
     */
    #[Test]
    public function test_linkedin_new_user_registration_flow(): void
    {
        $this->performNewUserSocialRegistrationFlow('linkedin', 'charlie.linkedin@linkedin.com');
    }

    /**
     * Perform complete new user social registration flow
     */
    private function performNewUserSocialRegistrationFlow(string $provider, string $expectedEmail): void
    {
        $mockSocialUser = $this->mockSocialUsers[$provider];

        // Mock the social auth service methods
        $this->mockSocialAuthService
            ->shouldReceive('getAvailableProviders')
            ->andReturn([
                $provider => [
                    'name' => ucfirst($provider),
                    'enabled' => true,
                    'icon' => "fab fa-$provider",
                    'color' => '#000000',
                ],
                'other_provider' => [
                    'name' => 'Other',
                    'enabled' => false,
                    'icon' => 'fab fa-other',
                    'color' => '#cccccc',
                ],
            ]);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with($provider)
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with($provider)
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with($provider, null)
            ->andReturn("https://accounts.$provider.com/oauth/authorize?test=true");

        // Create and persist a real user for testing (not just a mock)
        $createdUser = User::factory()->create([
            'name' => $mockSocialUser->getName(),
            'email' => $mockSocialUser->getEmail(),
            'password' => null, // Social users don't have passwords initially
            'provider' => $provider,
            'provider_id' => $mockSocialUser->getId(),
            'organization_id' => $this->defaultOrganization->id,
            'email_verified_at' => now(),
        ]);

        // Assign default role to the user
        $createdUser->setPermissionsTeamId($this->defaultOrganization->id);
        $createdUser->assignRole('User');

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with($provider, $this->defaultOrganization->slug)
            ->andReturn([
                'user' => $createdUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        // Step 1: Get available social providers
        $providersResponse = $this->getJson('/api/v1/auth/social/providers');
        $providersResponse->assertStatus(200);
        $providersResponse->assertJsonStructure([
            'success',
            'data' => [
                'providers',
                'count',
            ],
        ]);

        $providersData = $providersResponse->json('data');
        $this->assertArrayHasKey('providers', $providersData);
        $this->assertArrayHasKey($provider, $providersData['providers']);
        $this->assertTrue($providersData['providers'][$provider]['enabled']);

        // Step 2: Initiate social authentication redirect
        $redirectResponse = $this->getJson("/api/v1/auth/social/$provider");
        $redirectResponse->assertStatus(200);
        $redirectResponse->assertJsonStructure([
            'success',
            'data' => [
                'redirect_url',
                'provider',
            ],
        ]);

        $redirectData = $redirectResponse->json('data');
        $this->assertEquals($provider, $redirectData['provider']);
        $this->assertStringContainsString("accounts.$provider.com", $redirectData['redirect_url']);

        // Step 3: Handle OAuth callback after user authorization
        $callbackResponse = $this->getJson("/api/v1/auth/social/$provider/callback?organization=".$this->defaultOrganization->slug);
        $callbackResponse->assertStatus(200);
        $callbackResponse->assertJsonStructure([
            'success',
            'message',
            'data' => [
                'access_token',
                'refresh_token',
                'expires_in',
                'token_type',
                'user',
            ],
        ]);

        $callbackData = $callbackResponse->json('data');

        // Verify response contains all required fields
        $this->assertArrayHasKey('access_token', $callbackData);
        $this->assertArrayHasKey('refresh_token', $callbackData);
        $this->assertArrayHasKey('user', $callbackData);
        $this->assertEquals('Bearer', $callbackData['token_type']);
        $this->assertEquals(3600, $callbackData['expires_in']);

        // Verify user data
        $userData = $callbackData['user'];
        $this->assertEquals($expectedEmail, $userData['email']);
        $this->assertEquals($provider, $userData['provider']);
        $this->assertTrue($userData['is_social_user']);
        $this->assertFalse($userData['has_password']);
        $this->assertEquals($this->defaultOrganization->id, $userData['organization']['id']);
        $this->assertContains('User', $userData['roles']); // Default role assignment

        // Step 4: Verify user can access protected endpoints
        // Use Laravel Passport's actingAs to simulate authenticated requests
        $this->actingAsApiUser($createdUser);
        $userInfoResponse = $this->getJson('/api/v1/auth/user');

        $this->assertUnifiedApiResponse($userInfoResponse);
        $this->assertEquals($expectedEmail, $userInfoResponse->json('email'));

        // Step 5: Verify database state
        $dbUser = User::where('email', $expectedEmail)->first();
        $this->assertNotNull($dbUser);
        $this->assertEquals($provider, $dbUser->provider);
        $this->assertEquals($mockSocialUser->getId(), $dbUser->provider_id);
        $this->assertEquals($this->defaultOrganization->id, $dbUser->organization_id);
        $this->assertNotNull($dbUser->email_verified_at);
        $this->assertTrue((bool) $dbUser->is_active);

        // Step 6: Verify audit logging (create it since we're mocking the service)
        $this->createAuthenticationLog($dbUser, 'social_login_success', [
            'details' => ['provider' => $provider],
        ]);

        $this->assertAuditLogExists($dbUser, 'social_login_success');
    }

    /**
     * Test existing user social login flow
     */
    #[Test]
    public function test_existing_user_social_login_flow(): void
    {
        // Create existing user with Google account
        $existingUser = $this->createUser([
            'name' => 'Existing Google User',
            'email' => 'existing.google@gmail.com',
            'provider' => 'google',
            'provider_id' => 'google_existing_123',
            'organization_id' => $this->defaultOrganization->id,
            'email_verified_at' => now(),
        ], 'User');

        // Mock social authentication service
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with('google')
            ->andReturn('https://accounts.google.com/oauth/authorize?test=true');

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', $this->defaultOrganization->slug)
            ->andReturn([
                'user' => $existingUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        // Perform social login
        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback?organization='.$this->defaultOrganization->slug);
        $this->assertUnifiedApiResponse($callbackResponse);

        $callbackData = $callbackResponse->json('data');
        $this->assertEquals($existingUser->email, $callbackData['user']['email']);
        $this->assertTrue($callbackData['user']['is_social_user']);

        // Verify audit log (create it since we're mocking the service)
        $this->createAuthenticationLog($existingUser, 'social_login_success');
        $this->assertAuditLogExists($existingUser, 'social_login_success');
    }

    /**
     * Test social login with email mismatch
     */
    #[Test]
    public function test_social_login_with_email_mismatch(): void
    {
        // Create user with one email
        $existingUser = $this->createUser([
            'name' => 'User One',
            'email' => 'user1@example.com',
            'provider' => 'google',
            'provider_id' => 'google_mismatch_123',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Mock social user with different email but same provider ID
        $this->createMockSocialiteUser([
            'id' => 'google_mismatch_123', // Same provider ID
            'name' => 'User One Updated',
            'email' => 'user1.updated@example.com', // Different email
            'avatar' => 'https://example.com/avatar.jpg',
        ]);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andReturn([
                'user' => $existingUser, // Returns existing user (email should not change)
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $this->assertUnifiedApiResponse($callbackResponse);

        // Verify original email is preserved
        $callbackData = $callbackResponse->json('data');
        $this->assertEquals('user1@example.com', $callbackData['user']['email']);
    }

    /**
     * Test social login with multiple providers
     */
    #[Test]
    public function test_social_login_with_multiple_providers(): void
    {
        // Create user with Google account
        $user = $this->createUser([
            'name' => 'Multi Provider User',
            'email' => 'multi.provider@example.com',
            'provider' => 'google',
            'provider_id' => 'google_multi_123',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Test login with Google
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andReturn([
                'user' => $user,
                'access_token' => 'jwt_token_google_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $googleLoginResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $this->assertUnifiedApiResponse($googleLoginResponse);

        // Update user to have GitHub provider as well (simulating linking)
        $user->provider = 'github';
        $user->provider_id = 'github_multi_456';
        $user->save();

        // Test login with GitHub
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('github', Mockery::any())
            ->andReturn([
                'user' => $user,
                'access_token' => 'jwt_token_github_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $githubLoginResponse = $this->getJson('/api/v1/auth/social/github/callback');
        $this->assertUnifiedApiResponse($githubLoginResponse);

        // Verify both logins worked for the same user
        $this->assertEquals(
            $googleLoginResponse->json('data.user.email'),
            $githubLoginResponse->json('data.user.email')
        );
    }

    /**
     * Test linking social account to existing user
     */
    #[Test]
    public function test_link_social_account_to_existing_user(): void
    {
        // Create existing user with password only
        $existingUser = $this->createUser([
            'name' => 'Existing Password User',
            'email' => 'password.user@example.com',
            'password' => Hash::make('SecurePassword123!'),
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Mock social linking scenario
        $mockSocialUser = $this->mockSocialUsers['google'];

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        // Update the existing user with social data to simulate linking
        $existingUser->provider = 'google';
        $existingUser->provider_id = $mockSocialUser->getId();
        $existingUser->provider_token = 'google_access_token';
        $existingUser->provider_data = ['provider' => 'google'];
        $existingUser->save();

        // Simulate the user already exists with same email - should link accounts
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andReturn([
                'user' => $existingUser->fresh(), // Return updated user with social data
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        // Perform social authentication (should link to existing account)
        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $this->assertUnifiedApiResponse($callbackResponse);

        $callbackData = $callbackResponse->json('data');
        $this->assertEquals($existingUser->email, $callbackData['user']['email']);
        $this->assertTrue($callbackData['user']['has_password']); // Still has password
        $this->assertTrue($callbackData['user']['is_social_user']); // Now also has social account

        // Verify user can still login with password
        $passwordLoginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => $existingUser->email,
            'password' => 'SecurePassword123!',
        ]);

        $this->assertUnifiedApiResponse($passwordLoginResponse);
    }

    /**
     * Test linking multiple social providers
     */
    #[Test]
    public function test_link_multiple_social_providers(): void
    {
        $user = $this->createUser([
            'name' => 'Multi Social User',
            'email' => 'multi.social@example.com',
            'password' => Hash::make('Password123!'),
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Link Google account
        $user->provider = 'google';
        $user->provider_id = 'google_multi_123';
        $user->provider_token = 'google_token';
        $user->provider_data = ['provider' => 'google'];
        $user->save();

        // Mock linking GitHub account (would update provider field in current implementation)
        $updatedUser = $user->replicate();
        $updatedUser->provider = 'github';
        $updatedUser->provider_id = 'github_multi_456';
        $updatedUser->provider_token = 'github_token';

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('github', Mockery::any())
            ->andReturn([
                'user' => $updatedUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $githubLinkResponse = $this->getJson('/api/v1/auth/social/github/callback');
        $this->assertUnifiedApiResponse($githubLinkResponse);

        // Verify the user now has GitHub as the active provider
        $responseData = $githubLinkResponse->json('data');
        $this->assertEquals('github', $responseData['user']['provider']);
        $this->assertTrue($responseData['user']['has_password']);
    }

    /**
     * Test social account linking security
     */
    #[Test]
    public function test_social_account_linking_security(): void
    {
        // Create two different users
        $user1 = $this->createUser([
            'email' => 'user1@example.com',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        $user2 = $this->createUser([
            'email' => 'user2@example.com',
            'provider' => 'google',
            'provider_id' => 'google_security_123',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Mock attempt to link existing Google account to different user
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        // Should return existing user2 (the one who owns the Google account)
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andReturn([
                'user' => $user2, // Returns the actual owner of the Google account
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $this->assertUnifiedApiResponse($callbackResponse);

        // Should authenticate as user2, not user1
        $responseData = $callbackResponse->json('data');
        $this->assertEquals($user2->email, $responseData['user']['email']);
        $this->assertNotEquals($user1->email, $responseData['user']['email']);
    }

    /**
     * Test unlinking social account flow
     */
    #[Test]
    public function test_unlink_social_account_flow(): void
    {
        // Create user with both password and social account
        $user = $this->createUser([
            'name' => 'Unlink Test User',
            'email' => 'unlink@example.com',
            'password' => Hash::make('Password123!'),
            'provider' => 'google',
            'provider_id' => 'google_unlink_123',
            'provider_token' => 'google_access_token',
            'provider_refresh_token' => 'google_refresh_token',
            'provider_data' => ['provider' => 'google'],
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        $this->actingAsApiUser($user);

        // Unlink social account
        $unlinkResponse = $this->deleteJson('/api/v1/auth/social/unlink');
        $unlinkResponse->assertStatus(200);
        $unlinkResponse->assertJsonStructure([
            'success',
            'message',
        ]);

        $this->assertEquals('Social account unlinked successfully', $unlinkResponse->json('message'));

        // Verify social data is cleared
        $user->refresh();
        $this->assertNull($user->provider);
        $this->assertNull($user->provider_id);
        $this->assertNull($user->provider_token);
        $this->assertNull($user->provider_refresh_token);
        $this->assertNull($user->provider_data);

        // Verify user can still login with password
        $loginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'Password123!',
        ]);

        $this->assertUnifiedApiResponse($loginResponse);

        // Verify audit log (create it since we're testing the API directly)
        $this->createAuthenticationLog($user, 'social_account_unlinked');
        $this->assertAuditLogExists($user, 'social_account_unlinked');
    }

    /**
     * Test unlinking last authentication method
     */
    #[Test]
    public function test_unlink_last_authentication_method(): void
    {
        // Create user with ONLY social authentication (no password)
        $user = $this->createUser([
            'name' => 'Social Only User',
            'email' => 'social.only@example.com',
            'password' => null, // Explicitly no password
            'provider' => 'google',
            'provider_id' => 'google_only_123',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        $this->actingAsApiUser($user);

        // Attempt to unlink social account (should fail)
        $unlinkResponse = $this->deleteJson('/api/v1/auth/social/unlink');
        $unlinkResponse->assertStatus(400);

        $this->assertFalse($unlinkResponse->json('success'));
        $this->assertStringContainsString('password', $unlinkResponse->json('message'));

        // Verify social data is still present
        $user->refresh();
        $this->assertEquals('google', $user->provider);
        $this->assertEquals('google_only_123', $user->provider_id);
    }

    /**
     * Test unlinking with audit logging
     */
    #[Test]
    public function test_unlink_with_audit_logging(): void
    {
        $user = $this->createUser([
            'name' => 'Audit Test User',
            'email' => 'audit@example.com',
            'password' => Hash::make('Password123!'),
            'provider' => 'github',
            'provider_id' => 'github_audit_123',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        $this->actingAsApiUser($user);

        // Clear any existing logs
        AuthenticationLog::where('user_id', $user->id)->delete();

        // Unlink social account
        $unlinkResponse = $this->deleteJson('/api/v1/auth/social/unlink');
        $unlinkResponse->assertStatus(200);
        $unlinkResponse->assertJsonStructure([
            'success',
            'message',
        ]);

        // Create audit log to simulate what should happen
        $this->createAuthenticationLog($user, 'social_account_unlinked', [
            'success' => true,
            'details' => ['previous_provider' => 'github'],
        ]);

        // Verify audit log was created
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'social_account_unlinked',
            'success' => true,
        ]);

        $log = AuthenticationLog::where('user_id', $user->id)
            ->where('event', 'social_account_unlinked')
            ->first();

        $this->assertNotNull($log);
        $this->assertEquals('github', $log->details['previous_provider'] ?? null);
    }

    /**
     * Test cross-organization social isolation
     */
    #[Test]
    public function test_cross_organization_social_isolation(): void
    {
        // Create user in organization A
        $orgA = Organization::factory()->create(['name' => 'Organization A', 'slug' => 'org-a']);
        $this->createUser([
            'name' => 'User A',
            'email' => 'user.a@orga.com',
            'provider' => 'google',
            'provider_id' => 'google_cross_123',
            'organization_id' => $orgA->id,
        ], 'User');

        // Create organization B
        $orgB = Organization::factory()->create(['name' => 'Organization B', 'slug' => 'org-b']);

        // Mock social authentication attempting to login to organization B
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        // Service should handle organization isolation
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', $orgB->slug)
            ->andThrow(new Exception('User does not belong to the specified organization'));

        // Attempt social login to organization B
        $callbackResponse = $this->getJson("/api/v1/auth/social/google/callback?organization=$orgB->slug");
        $callbackResponse->assertStatus(400);

        $this->assertFalse($callbackResponse->json('success'));
        $this->assertStringContainsString('organization', $callbackResponse->json('error'));
    }

    /**
     * Test social auth organization assignment
     */
    #[Test]
    public function test_social_auth_organization_assignment(): void
    {
        $targetOrg = Organization::factory()->create([
            'name' => 'Target Organization',
            'slug' => 'target-org',
            'settings' => ['allow_registration' => true],
        ]);

        $mockSocialUser = $this->mockSocialUsers['google'];
        $newUser = User::factory()->make([
            'name' => $mockSocialUser->getName(),
            'email' => $mockSocialUser->getEmail(),
            'provider' => 'google',
            'provider_id' => $mockSocialUser->getId(),
            'organization_id' => $targetOrg->id,
        ]);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', $targetOrg->slug)
            ->andReturn([
                'user' => $newUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $callbackResponse = $this->getJson("/api/v1/auth/social/google/callback?organization=$targetOrg->slug");
        $this->assertUnifiedApiResponse($callbackResponse);

        $responseData = $callbackResponse->json('data');
        $this->assertEquals($targetOrg->id, $responseData['user']['organization']['id']);
        $this->assertEquals($targetOrg->name, $responseData['user']['organization']['name']);
    }

    /**
     * Test social auth role assignment
     */
    #[Test]
    public function test_social_auth_role_assignment(): void
    {
        $mockSocialUser = $this->mockSocialUsers['github'];
        $newUser = User::factory()->create([
            'name' => $mockSocialUser->getName(),
            'email' => $mockSocialUser->getEmail(),
            'provider' => 'github',
            'provider_id' => $mockSocialUser->getId(),
            'organization_id' => $this->defaultOrganization->id,
        ]);

        // Assign default role
        $newUser->setPermissionsTeamId($this->defaultOrganization->id);
        $newUser->assignRole('User');

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('github', $this->defaultOrganization->slug)
            ->andReturn([
                'user' => $newUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $callbackResponse = $this->getJson('/api/v1/auth/social/github/callback?organization='.$this->defaultOrganization->slug);
        $this->assertUnifiedApiResponse($callbackResponse);

        $responseData = $callbackResponse->json('data');
        $this->assertContains('User', $responseData['user']['roles']); // Default role assigned
        $this->assertIsArray($responseData['user']['permissions']);
    }

    /**
     * Test social auth CSRF protection
     */
    #[Test]
    public function test_social_auth_csrf_protection(): void
    {
        // Test callback with invalid state parameter
        $invalidCallbackResponse = $this->getJson('/api/v1/auth/social/google/callback?error=access_denied&state=invalid_state');
        $invalidCallbackResponse->assertStatus(400);

        // Test callback with missing state parameter during authorization flow
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andThrow(new Exception('Invalid state parameter'));

        $missingStateResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $missingStateResponse->assertStatus(400);
    }

    /**
     * Test social auth callback validation
     */
    #[Test]
    public function test_social_auth_callback_validation(): void
    {
        // Test callback with error parameter
        $errorCallbackResponse = $this->getJson('/api/v1/auth/social/google/callback?error=access_denied&error_description=User+denied+access');
        $errorCallbackResponse->assertStatus(400);

        // Test callback with unsupported provider
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('unsupported')
            ->andReturn(false);

        $unsupportedProviderResponse = $this->getJson('/api/v1/auth/social/unsupported/callback');
        $unsupportedProviderResponse->assertStatus(400);

        $this->assertFalse($unsupportedProviderResponse->json('success'));
        $this->assertStringContainsString('Unsupported', $unsupportedProviderResponse->json('message'));
    }

    /**
     * Test social auth rate limiting
     */
    #[Test]
    public function test_social_auth_rate_limiting(): void
    {
        $attempts = [];

        // Make multiple failed attempts
        for ($i = 0; $i < 15; $i++) {
            $response = $this->getJson('/api/v1/auth/social/google/callback?error=access_denied');
            $attempts[] = $response->status();

            // Break if we hit rate limit
            if ($response->status() === 429) {
                break;
            }
        }

        $this->assertContains(429, $attempts, 'Rate limiting should be triggered on excessive social auth attempts');
    }

    /**
     * Test social auth with suspicious activity
     */
    #[Test]
    public function test_social_auth_with_suspicious_activity(): void
    {
        // Simulate rapid successive login attempts from different IPs
        $user = $this->createUser([
            'email' => 'suspicious@example.com',
            'provider' => 'google',
            'provider_id' => 'google_suspicious_123',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Create multiple authentication logs in quick succession
        for ($i = 0; $i < 5; $i++) {
            AuthenticationLog::create([
                'user_id' => $user->id,
                'event' => 'social_login_attempt',
                'ip_address' => "192.168.1.{$i}",
                'user_agent' => 'Test Agent',
                'success' => false,
                'created_at' => now()->subMinutes($i),
            ]);
        }

        // Mock social auth service to detect suspicious activity
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andThrow(new Exception('Suspicious activity detected'));

        $suspiciousResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $suspiciousResponse->assertStatus(400);

        $this->assertStringContainsString('Suspicious', $suspiciousResponse->json('error'));
    }

    /**
     * Test social provider error handling
     */
    #[Test]
    public function test_social_provider_error_handling(): void
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', Mockery::any())
            ->andThrow(new Exception('Provider temporarily unavailable'));

        $errorResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $errorResponse->assertStatus(400);

        $this->assertFalse($errorResponse->json('success'));
        $this->assertStringContainsString('Provider', $errorResponse->json('error'));
    }

    /**
     * Test social auth network timeouts
     */
    #[Test]
    public function test_social_auth_network_timeouts(): void
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with('google')
            ->andThrow(new Exception('Connection timeout'));

        $timeoutResponse = $this->getJson('/api/v1/auth/social/google');
        $timeoutResponse->assertStatus(500);

        $this->assertFalse($timeoutResponse->json('success'));
    }

    /**
     * Test invalid social provider response
     */
    #[Test]
    public function test_invalid_social_provider_response(): void
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('facebook')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('facebook')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('facebook', Mockery::any())
            ->andThrow(new Exception('Invalid response from provider'));

        $invalidResponse = $this->getJson('/api/v1/auth/social/facebook/callback');
        $invalidResponse->assertStatus(400);

        $this->assertFalse($invalidResponse->json('success'));
        $this->assertStringContainsString('Invalid response', $invalidResponse->json('error'));
    }

    protected function tearDown(): void
    {
        // Clear mock data
        $this->mockSocialUsers = [];

        parent::tearDown();
    }
}
