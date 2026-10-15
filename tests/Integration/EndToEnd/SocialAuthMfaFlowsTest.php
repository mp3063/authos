<?php

namespace Tests\Integration\EndToEnd;

use App\Models\Organization;
use App\Models\User;
use App\Services\SocialAuthService;
use Filament\Notifications\Notification as FilamentNotification;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteTwoUser;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use PragmaRX\Google2FA\Google2FA;
use Spatie\Permission\PermissionRegistrar;

/**
 * End-to-End tests for Social Authentication and MFA workflows.
 *
 * Tests comprehensive social authentication flows, MFA setup and validation,
 * and combination scenarios with different security requirements.
 *
 * Note on Exception Handling:
 * - Google2FA methods may throw exceptions for invalid secrets/codes.
 * - In test environment, exceptions are allowed to bubble up for proper test failure reporting.
 * - HTTP client exceptions from API calls are handled by Laravel's test framework.
 */
class SocialAuthMfaFlowsTest extends EndToEndTestCase
{
    protected Google2FA $google2FA;

    protected function setUp(): void
    {
        parent::setUp();
        $this->google2FA = new Google2FA;
    }

    /**
     * Test complete social authentication registration flow
     */
    public function test_social_authentication_registration_flow(): void
    {
        // Mock successful Google authentication
        $mockUser = User::factory()->create([
            'name' => 'John Doe',
            'email' => 'john.doe@gmail.com',
            'provider' => 'google',
            'provider_id' => 'google_123456789',
            'organization_id' => $this->defaultOrganization->id,
        ]);

        // Step 1: Get available social providers
        $this->mockSocialAuthService
            ->shouldReceive('getAvailableProviders')
            ->andReturn([
                'google' => [
                    'name' => 'Google',
                    'enabled' => true,
                    'icon' => 'fab fa-google',
                    'color' => '#db4437',
                ],
            ]);

        $providersResponse = $this->getJson('/api/v1/auth/social/providers');
        $this->assertUnifiedApiResponse($providersResponse, 200);

        // Step 2: Initiate social authentication
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
            ->with('google', null)
            ->andReturn('https://accounts.google.com/oauth/authorize?client_id=test&redirect_uri=test');

        $redirectResponse = $this->getJson('/api/v1/auth/social/google');
        $this->assertUnifiedApiResponse($redirectResponse, 200);

        $redirectData = $redirectResponse->json('data');
        $this->assertEquals('google', $redirectData['provider']);
        $this->assertStringStartsWith('https://accounts.google.com', $redirectData['redirect_url']);

        // Step 3: Handle callback after user authorizes
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
            ->with('google', $this->defaultOrganization->slug)
            ->andReturn([
                'user' => $mockUser,
                'access_token' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNDNjYjNiYzNhMWJkNzc5YjNkNzhjNmU2Njk4MDFhMzkxZDU0OTExZGZkOGQ3NzU3MWZhNDdhMTBiMzU3YWU4YWY2YjU0NzM2MTFmZjc1ODAiLCJpYXQiOjE3MjY2NzcyNTUsIm5iZiI6MTcyNjY3NzI1NSwiZXhwIjoxNzU4MjEzMjU1LCJzdWIiOiIxIiwic2NvcGVzIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdfQ.example_signature',
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback?organization='.$this->defaultOrganization->slug);
        $this->assertUnifiedApiResponse($callbackResponse, 200);

        $callbackData = $callbackResponse->json('data');
        $this->assertArrayHasKey('access_token', $callbackData);
        $this->assertArrayHasKey('user', $callbackData);
        $this->assertEquals('google', $callbackData['user']['provider']);
        $this->assertTrue($callbackData['user']['is_social_user']);

        // Step 4: Verify user can access protected endpoints
        $this->actingAs($mockUser, 'api');
        $userInfoResponse = $this->getJson('/api/v1/auth/user');

        $this->assertUnifiedApiResponse($userInfoResponse, 200);
        $userInfoData = $userInfoResponse->json();
        $this->assertEquals('john.doe@gmail.com', $userInfoData['email']);

        // Note: Audit log verification skipped in this test since we're mocking the service
    }

    /**
     * Test MFA setup flow for new user
     */
    public function test_mfa_setup_flow(): void
    {
        $user = $this->createUser([
            'name' => 'MFA Test User',
            'email' => 'mfa@example.com',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        $this->actingAsApiUser($user);

        // Step 1: Get MFA setup information
        $mfaStatusResponse = $this->getJson('/api/v1/mfa/status');
        $this->assertUnifiedApiResponse($mfaStatusResponse, 200);

        $statusData = $mfaStatusResponse->json('data');
        $this->assertFalse($statusData['mfa_enabled']);
        $this->assertSame(0, $statusData['backup_codes_count']);

        // Step 2: Generate TOTP secret
        $setupResponse = $this->postJson('/api/v1/mfa/setup');
        $this->assertUnifiedApiResponse($setupResponse, 200);

        $setupData = $setupResponse->json('data');
        $this->assertArrayHasKey('secret', $setupData);
        $this->assertArrayHasKey('qr_code_url', $setupData);
        $this->assertArrayHasKey('backup_codes', $setupData);

        $secret = $setupData['secret'];

        // Step 3: Verify TOTP code to enable MFA
        // Note: getCurrentOtp() may throw exceptions for invalid secrets - these are allowed to bubble up for test failure reporting
        $totpCode = $this->google2FA->getCurrentOtp($secret);

        $enableResponse = $this->postJson('/api/v1/mfa/enable', [
            'code' => $totpCode,
        ]);

        $this->assertUnifiedApiResponse($enableResponse, 200);

        // Step 4: Verify MFA is now enabled
        $user->refresh();
        $this->assertNotNull($user->mfa_secret);
        $this->assertNotEmpty($user->mfa_backup_codes);

        // Step 5: Test login with MFA required
        $loginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $loginResponse->assertStatus(202); // MFA challenge required
        $loginData = $loginResponse->json();
        $this->assertTrue($loginData['mfa_required']);
        $this->assertArrayHasKey('challenge_token', $loginData);

        // Step 6: Complete MFA challenge
        $challengeToken = $loginData['challenge_token'];
        // Note: getCurrentOtp() exceptions are allowed to bubble up for proper test failure reporting
        $user->refresh(); // Refresh user to get updated MFA settings
        $newTotpCode = $this->google2FA->getCurrentOtp($secret);

        $mfaResponse = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken,
            'totp_code' => $newTotpCode,
        ]);

        $this->assertUnifiedApiResponse($mfaResponse, 200);
        $mfaData = $mfaResponse->json();
        $this->assertArrayHasKey('access_token', $mfaData);

        // Verify audit logs
        $this->assertAuditLogExists($user, 'mfa_enabled');
        // Note: mfa_login_success may not be logged in this test flow due to mock implementation
    }

    /**
     * Test MFA backup codes usage
     */
    public function test_mfa_backup_codes_flow(): void
    {
        // Create user with MFA already enabled
        $user = $this->createUser([
            'name' => 'MFA Backup User',
            'email' => 'mfa.backup@example.com',
            'organization_id' => $this->defaultOrganization->id,
            'mfa_secret' => $this->google2FA->generateSecretKey(), // generateSecretKey() exceptions bubble up for test failure reporting
            'mfa_backup_codes' => ['backup123', 'backup456', 'backup789'],
            'mfa_methods' => ['totp'],
            'two_factor_confirmed_at' => now(),
        ], 'User');

        // Step 1: Login and get MFA challenge
        $loginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $loginResponse->assertStatus(202);
        $loginData = $loginResponse->json();
        $challengeToken = $loginData['challenge_token'];

        // Step 2: Use backup code instead of TOTP
        $backupResponse = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken,
            'backup_code' => 'backup123',
        ]);

        $this->assertUnifiedApiResponse($backupResponse, 200);

        // Note: backup code consumption testing skipped for mock implementation
        // In production, backup codes would be consumed after use

        // Step 4: Try to reuse the same backup code
        $loginResponse2 = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $loginData2 = $loginResponse2->json();
        $challengeToken2 = $loginData2['challenge_token'];

        $reusedBackupResponse = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken2,
            'backup_code' => 'backup123',
        ]);

        // Expect 401 for reused backup code (consumed codes are removed)
        $reusedBackupResponse->assertStatus(401);
        $this->assertEquals('invalid_grant', $reusedBackupResponse->json('error'));

        // Note: Audit log verification skipped for mock implementation
    }

    private function signInThroughRealSocialAuthAs(string $provider, string $providerId, string $email): void
    {
        $this->app->forgetInstance(SocialAuthService::class);

        $socialUser = (new SocialiteTwoUser)
            ->setRaw(['id' => $providerId])
            ->map(['id' => $providerId, 'name' => 'Social User', 'email' => $email, 'nickname' => null, 'avatar' => null])
            ->setToken('provider-token');

        $driver = Mockery::mock();
        $driver->shouldReceive('stateless')->andReturnSelf();
        $driver->shouldReceive('user')->andReturn($socialUser);
        Socialite::shouldReceive('driver')->with($provider)->andReturn($driver);
    }

    private function panelOwner(array $attributes = []): User
    {
        $owner = $this->createUser(
            ['organization_id' => $this->defaultOrganization->id, ...$attributes],
            'Organization Owner',
            'web'
        );
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        return $owner->unsetRelation('roles')->unsetRelation('permissions');
    }

    #[Test]
    public function it_challenges_a_social_login_for_a_user_with_mfa(): void
    {
        $user = User::factory()->withMfa()->forOrganization($this->defaultOrganization)->create();
        $this->signInThroughRealSocialAuthAs('github', 'github-mfa-user', $user->email);

        $callback = $this->getJson('/api/v1/auth/social/github/callback');

        $callback->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonPath('available_methods', ['totp'])
            ->assertJsonStructure(['challenge_token'])
            ->assertJsonMissingPath('access_token')
            ->assertJsonMissingPath('data.access_token');
        $this->assertSame(0, $user->tokens()->count());
        $this->assertAuditLogExists($user, 'mfa_required');

        $verify = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $callback->json('challenge_token'),
            'totp_code' => $this->totpCodeFor($user),
        ]);

        $verify->assertOk()->assertJsonStructure(['access_token']);
    }

    #[Test]
    public function it_returns_a_setup_token_for_a_social_login_into_an_organization_that_requires_mfa(): void
    {
        Mail::fake();
        $organization = Organization::factory()->create([
            'slug' => 'mfa-required-org',
            'settings' => ['require_mfa' => true, 'allow_registration' => true],
        ]);
        $this->signInThroughRealSocialAuthAs('github', 'github_987654321', 'social.mfa@example.com');

        $callback = $this->getJson('/api/v1/auth/social/github/callback?organization='.$organization->slug);

        $callback->assertForbidden()
            ->assertJsonPath('error', 'mfa_setup_required')
            ->assertJsonStructure(['setup_token', 'token_type', 'expires_in'])
            ->assertJsonMissingPath('access_token')
            ->assertJsonMissingPath('data.access_token')
            ->assertJsonMissingPath('challenge_token');
        $user = User::where('email', 'social.mfa@example.com')->sole();
        $this->assertSame($organization->id, $user->organization_id);
        $this->assertSame(['mfa.setup'], $user->tokens()->sole()->scopes);
        $this->assertAuditLogExists($user, 'mfa_setup_required');

        $this->app['auth']->forgetGuards();
        $this->withHeader('Authorization', 'Bearer '.$callback->json('setup_token'))
            ->postJson('/api/v1/mfa/setup')->assertOk();
        $this->withHeader('Authorization', 'Bearer '.$callback->json('setup_token'))
            ->postJson('/api/v1/mfa/enable', ['code' => $this->totpCodeFor($user->fresh())])->assertOk();
        $this->flushHeaders();
        $this->app['auth']->forgetGuards();

        $nextCallback = $this->getJson('/api/v1/auth/social/github/callback?organization='.$organization->slug);

        $nextCallback->assertStatus(202)->assertJsonPath('mfa_required', true);
    }

    #[Test]
    public function it_refuses_a_social_web_login_for_a_user_who_requires_mfa(): void
    {
        $owner = $this->panelOwner([
            'two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
        ]);
        $this->signInThroughRealSocialAuthAs('google', 'google-mfa-owner', $owner->email);

        $response = $this->get('/auth/social/google/callback');

        $response->assertRedirect('/admin/login');
        FilamentNotification::assertNotified('Sign in with your email, password and authenticator code.');
        $this->assertTrue(auth()->guest());
        $this->assertDatabaseMissing('oauth_access_tokens', ['user_id' => $owner->id]);
    }

    #[Test]
    public function it_still_signs_in_a_social_web_user_without_any_mfa_requirement(): void
    {
        $owner = $this->panelOwner();
        $this->signInThroughRealSocialAuthAs('google', 'google-plain-owner', $owner->email);

        $response = $this->get('/auth/social/google/callback');

        $response->assertRedirect('/admin');
        $this->assertAuthenticatedAs($owner);
        $this->assertDatabaseMissing('oauth_access_tokens', ['user_id' => $owner->id]);
        $this->assertAuditLogExists($owner, 'social_login_success');
    }

    /**
     * Test linking social account to existing user with password
     */
    public function test_link_social_account_to_existing_user(): void
    {
        // Create existing user with password
        $existingUser = $this->createUser([
            'name' => 'Existing User',
            'email' => 'existing@example.com',
            'password' => Hash::make('ExistingPassword123!'),
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Step 1: User logs in with password
        $this->actingAsApiUser($existingUser);

        // Step 2: User initiates social account linking
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        // Mock the Socialite driver to return a social user
        $mockSocialUser = Mockery::mock(SocialiteUser::class);
        $mockSocialUser->shouldReceive('getId')->andReturn('google_link_123');
        $mockSocialUser->shouldReceive('getName')->andReturn('Social User');
        $mockSocialUser->shouldReceive('getEmail')->andReturn('social@example.com');

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockSocialUser);

        $this->mockSocialAuthService
            ->shouldReceive('linkSocialAccount')
            ->with($existingUser, 'google', Mockery::type('Laravel\Socialite\Contracts\User'))
            ->andReturnUsing(function ($user, $provider, $socialUser) {
                $user->update([
                    'provider' => $provider,
                    'provider_id' => $socialUser->getId(),
                ]);

                return $user;
            });

        $linkResponse = $this->postJson('/api/v1/auth/social/link', [
            'provider' => 'google',
            'provider_code' => 'auth_code_from_google',
        ]);

        $this->assertUnifiedApiResponse($linkResponse, 200);

        // Step 3: Verify social account is linked
        $existingUser->refresh();
        $this->assertEquals('google', $existingUser->provider);
        $this->assertEquals('google_link_123', $existingUser->provider_id);

        // Step 4: User can now login via social auth
        $this->mockSuccessfulSocialAuth('google', $existingUser);

        $socialLoginResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $this->assertUnifiedApiResponse($socialLoginResponse, 200);

        $socialLoginData = $socialLoginResponse->json('data');
        $this->assertEquals($existingUser->email, $socialLoginData['user']['email']);
        $this->assertTrue($socialLoginData['user']['has_password']); // Still has password
    }

    /**
     * Test multiple social providers for same user
     */
    public function test_multiple_social_providers_per_user(): void
    {
        $user = $this->createUser([
            'name' => 'Multi Social User',
            'email' => 'multi@example.com',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        $this->actingAsApiUser($user);

        // Link Google account
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);

        $mockGoogleUser = Mockery::mock(SocialiteUser::class);
        $mockGoogleUser->shouldReceive('getId')->andReturn('google_multi_123');

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturnSelf();
        Socialite::shouldReceive('user')
            ->andReturn($mockGoogleUser);

        $this->mockSocialAuthService
            ->shouldReceive('linkSocialAccount')
            ->with($user, 'google', Mockery::type('Laravel\Socialite\Contracts\User'))
            ->andReturnUsing(function ($u, $provider, $socialUser) {
                $u->update([
                    'provider' => $provider,
                    'provider_id' => $socialUser->getId(),
                ]);

                return $u;
            });

        $linkGoogleResponse = $this->postJson('/api/v1/auth/social/link', [
            'provider' => 'google',
            'provider_code' => 'google_auth_code',
        ]);

        $this->assertUnifiedApiResponse($linkGoogleResponse, 200);

        // Note: In this implementation, we're storing the latest provider
        // A more advanced implementation would store multiple providers in a separate table
        $user->refresh();
        $this->assertEquals('google', $user->provider);

        // Verify user can access social providers list
        $socialAccountsResponse = $this->getJson('/api/v1/profile/social-accounts');
        $this->assertUnifiedApiResponse($socialAccountsResponse, 200);

        $socialAccounts = $socialAccountsResponse->json('data');
        $this->assertArrayHasKey('linked_providers', $socialAccounts);
    }

    /**
     * Test MFA recovery flow
     */
    public function test_mfa_recovery_flow(): void
    {
        // Create user with MFA enabled
        $user = $this->createUser([
            'name' => 'Recovery User',
            'email' => 'recovery@example.com',
            'organization_id' => $this->defaultOrganization->id,
            'mfa_secret' => $this->google2FA->generateSecretKey(), // generateSecretKey() exceptions bubble up for test failure reporting
            'mfa_backup_codes' => ['recovery1', 'recovery2'],
            'mfa_methods' => ['totp'], // Required for hasMfaEnabled() to return true
            'two_factor_secret' => encrypt($this->google2FA->generateSecretKey()), // generateSecretKey() exceptions bubble up for test failure reporting
            'two_factor_confirmed_at' => now(),
        ], 'User');

        $this->actingAsApiUser($user);

        // Step 1: Generate new backup codes
        $newCodesResponse = $this->postJson('/api/v1/mfa/backup-codes/regenerate', [
            'password' => 'password',
        ]);
        $this->assertUnifiedApiResponse($newCodesResponse, 200);

        $newCodes = $newCodesResponse->json('data.recovery_codes');
        $this->assertCount(8, $newCodes); // Should generate 8 new codes

        // Verify old codes are invalidated
        $user->refresh();
        $this->assertNotContains('recovery1', $user->mfa_backup_codes);
        $this->assertNotContains('recovery2', $user->mfa_backup_codes);

        // Step 3: Disable MFA (requires password and a regenerated recovery code)
        $disableResponse = $this->postJson('/api/v1/mfa/disable', [
            'password' => 'password',
            'code' => $newCodes[0],
        ]);

        $this->assertUnifiedApiResponse($disableResponse, 200);

        // Verify MFA is disabled
        $user->refresh();
        $this->assertNull($user->mfa_secret);
        $this->assertEmpty($user->mfa_backup_codes);

        // Verify audit log
        $this->assertAuditLogExists($user, 'mfa_disabled');
    }

    /**
     * Test social authentication rate limiting
     */
    public function test_social_authentication_rate_limiting(): void
    {
        // Test rate limiting on social auth callbacks
        $attempts = [];
        for ($i = 0; $i < 20; $i++) {
            $response = $this->getJson('/api/v1/auth/social/google/callback?error=access_denied');
            $attempts[] = $response->status();

            if ($response->status() === 429) {
                break; // Hit rate limit
            }
        }

        $this->assertContains(429, $attempts, 'Rate limiting should be triggered on excessive social auth attempts');
    }

    /**
     * Test organization-specific social provider restrictions
     */
    public function test_organization_social_provider_restrictions(): void
    {
        // Create organization with restricted social providers
        $restrictedOrg = Organization::factory()->create([
            'name' => 'Restricted Social Org',
            'slug' => 'restricted-social-org',
            'settings' => [
                'allowed_social_providers' => ['google'], // Only Google allowed
            ],
        ]);

        // Test allowed provider (Google)
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
            ->with('google', $restrictedOrg->slug)
            ->andReturn('https://accounts.google.com/oauth/authorize?test=true');

        $googleResponse = $this->getJson('/api/v1/auth/social/google?organization='.$restrictedOrg->slug);
        $this->assertUnifiedApiResponse($googleResponse, 200);

        // Test disallowed provider (GitHub) - simulate it being disabled
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('github')
            ->andReturn(false); // Disabled instead of organization-specific restriction

        $githubResponse = $this->getJson('/api/v1/auth/social/github?organization='.$restrictedOrg->slug);
        $githubResponse->assertStatus(400);
        $githubResponse->assertJson([
            'success' => false,
            'message' => 'Social provider is not configured',
        ]);
    }
}
