<?php

namespace Tests\Integration\EndToEnd;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FA\Google2FA;

/**
 * End-to-End tests for Social Authentication and MFA workflows.
 *
 * Tests comprehensive social authentication flows, MFA setup and validation,
 * and combination scenarios with different security requirements.
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
        $mockUser = User::factory()->make([
            'name' => 'John Doe',
            'email' => 'john.doe@gmail.com',
            'provider' => 'google',
            'provider_id' => 'google_123456789',
            'organization_id' => $this->defaultOrganization->id,
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
            ->shouldReceive('getRedirectUrl')
            ->with('google')
            ->andReturn('https://accounts.google.com/oauth/authorize?test=true');

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', $this->defaultOrganization->slug)
            ->andReturn([
                'user' => $mockUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ]);

        // Step 1: Get available social providers
        $providersResponse = $this->getJson('/api/v1/auth/social/providers');
        $this->assertUnifiedApiResponse($providersResponse, 200);

        // Step 2: Initiate social authentication
        $redirectResponse = $this->getJson('/api/v1/auth/social/google');
        $this->assertUnifiedApiResponse($redirectResponse, 200);

        $redirectData = $redirectResponse->json('data');
        $this->assertEquals('google', $redirectData['provider']);
        $this->assertStringStartsWith('https://accounts.google.com', $redirectData['redirect_url']);

        // Step 3: Handle callback after user authorizes
        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback?organization='.$this->defaultOrganization->slug);
        $this->assertUnifiedApiResponse($callbackResponse, 200);

        $callbackData = $callbackResponse->json('data');
        $this->assertArrayHasKey('access_token', $callbackData);
        $this->assertArrayHasKey('user', $callbackData);
        $this->assertEquals('google', $callbackData['user']['provider']);
        $this->assertTrue($callbackData['user']['is_social_user']);

        // Step 4: Verify user can access protected endpoints
        $userToken = $callbackData['access_token'];
        $userInfoResponse = $this->getJson('/api/v1/auth/user', [
            'Authorization' => 'Bearer '.$userToken,
        ]);

        $this->assertUnifiedApiResponse($userInfoResponse, 200);
        $this->assertEquals('john.doe@gmail.com', $userInfoResponse->json('email'));

        // Verify audit log
        $user = User::where('email', 'john.doe@gmail.com')->first();
        $this->assertAuditLogExists($user, 'social_login_success');
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
        $this->assertFalse($statusData['enabled']);
        $this->assertEmpty($statusData['backup_codes']);

        // Step 2: Generate TOTP secret
        $setupResponse = $this->postJson('/api/v1/mfa/setup');
        $this->assertUnifiedApiResponse($setupResponse, 200);

        $setupData = $setupResponse->json('data');
        $this->assertArrayHasKey('secret', $setupData);
        $this->assertArrayHasKey('qr_code', $setupData);
        $this->assertArrayHasKey('backup_codes', $setupData);

        $secret = $setupData['secret'];
        $backupCodes = $setupData['backup_codes'];

        // Step 3: Verify TOTP code to enable MFA
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
        $newTotpCode = $this->google2FA->getCurrentOtp($secret);

        $mfaResponse = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken,
            'code' => $newTotpCode,
        ]);

        $this->assertUnifiedApiResponse($mfaResponse, 200);
        $mfaData = $mfaResponse->json();
        $this->assertArrayHasKey('access_token', $mfaData);

        // Verify audit logs
        $this->assertAuditLogExists($user, 'mfa_enabled');
        $this->assertAuditLogExists($user, 'mfa_login_success');
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
            'mfa_secret' => $this->google2FA->generateSecretKey(),
            'mfa_backup_codes' => ['backup123', 'backup456', 'backup789'],
        ], 'User');

        // Step 1: Login and get MFA challenge
        $loginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $loginResponse->assertStatus(202);
        $challengeToken = $loginResponse->json('challenge_token');

        // Step 2: Use backup code instead of TOTP
        $backupResponse = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken,
            'backup_code' => 'backup123',
        ]);

        $this->assertUnifiedApiResponse($backupResponse, 200);

        // Step 3: Verify backup code is consumed
        $user->refresh();
        $this->assertNotContains('backup123', $user->mfa_backup_codes);
        $this->assertContains('backup456', $user->mfa_backup_codes);

        // Step 4: Try to reuse the same backup code
        $loginResponse2 = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $challengeToken2 = $loginResponse2->json('challenge_token');

        $reusedBackupResponse = $this->postJson('/api/v1/auth/mfa/verify', [
            'challenge_token' => $challengeToken2,
            'backup_code' => 'backup123', // Already used
        ]);

        $reusedBackupResponse->assertStatus(400);

        // Verify audit logs
        $this->assertAuditLogExists($user, 'mfa_backup_code_used');
    }

    /**
     * Test social authentication with MFA required organization
     */
    public function test_social_auth_with_mfa_required_organization(): void
    {
        // Create organization that requires MFA
        $mfaOrg = Organization::factory()->create([
            'name' => 'MFA Required Organization',
            'slug' => 'mfa-required-org',
            'settings' => [
                'mfa_required' => true,
                'allow_registration' => true,
            ],
        ]);

        // Mock social authentication for new user
        $mockUser = User::factory()->make([
            'name' => 'Social MFA User',
            'email' => 'social.mfa@example.com',
            'provider' => 'github',
            'provider_id' => 'github_987654321',
            'organization_id' => $mfaOrg->id,
        ]);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('github')
            ->andReturn(true);

        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with('github')
            ->andReturn('https://github.com/login/oauth/authorize?test=true');

        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('github', $mfaOrg->slug)
            ->andReturn([
                'user' => $mockUser,
                'access_token' => 'jwt_token_'.uniqid(),
                'refresh_token' => 'refresh_token_'.uniqid(),
                'expires_in' => 3600,
                'token_type' => 'Bearer',
                'mfa_required' => true, // Organization requires MFA
            ]);

        // Step 1: Complete social authentication
        $callbackResponse = $this->getJson('/api/v1/auth/social/github/callback?organization='.$mfaOrg->slug);

        // Should succeed but require MFA setup
        $this->assertUnifiedApiResponse($callbackResponse, 200);
        $callbackData = $callbackResponse->json('data');

        $this->assertTrue($callbackData['mfa_setup_required']);
        $this->assertArrayHasKey('access_token', $callbackData);

        // Step 2: User must set up MFA to fully access the system
        $user = User::where('email', 'social.mfa@example.com')->first();
        $this->actingAsApiUser($user);

        $mfaSetupResponse = $this->postJson('/api/v1/mfa/setup');
        $this->assertUnifiedApiResponse($mfaSetupResponse, 200);

        $secret = $mfaSetupResponse->json('data.secret');
        $totpCode = $this->google2FA->getCurrentOtp($secret);

        $enableMfaResponse = $this->postJson('/api/v1/mfa/enable', [
            'code' => $totpCode,
        ]);

        $this->assertUnifiedApiResponse($enableMfaResponse, 200);

        // Step 3: Subsequent logins require MFA
        $nextLoginResponse = $this->getJson('/api/v1/auth/social/github/callback?organization='.$mfaOrg->slug);
        $this->assertUnifiedApiResponse($nextLoginResponse, 200);

        $nextCallbackData = $nextLoginResponse->json('data');
        $this->assertFalse($nextCallbackData['mfa_setup_required'] ?? false);
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

        $this->mockSocialAuthService
            ->shouldReceive('linkSocialAccount')
            ->with($existingUser, 'google')
            ->andReturn([
                'provider' => 'google',
                'provider_id' => 'google_link_123',
                'provider_token' => 'google_access_token',
            ]);

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
            ->shouldReceive('linkSocialAccount')
            ->with($user, 'google')
            ->andReturn([
                'provider' => 'google',
                'provider_id' => 'google_multi_123',
                'provider_token' => 'google_token',
            ]);

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
            'mfa_secret' => $this->google2FA->generateSecretKey(),
            'mfa_backup_codes' => ['recovery1', 'recovery2'],
        ], 'User');

        $this->actingAsApiUser($user);

        // Step 1: Generate new backup codes
        $newCodesResponse = $this->postJson('/api/v1/mfa/backup-codes/regenerate');
        $this->assertUnifiedApiResponse($newCodesResponse, 200);

        $newCodes = $newCodesResponse->json('data.backup_codes');
        $this->assertCount(8, $newCodes); // Should generate 8 new codes

        // Step 2: Verify old codes are invalidated
        $user->refresh();
        $this->assertNotContains('recovery1', $user->mfa_backup_codes);
        $this->assertNotContains('recovery2', $user->mfa_backup_codes);

        // Step 3: Disable MFA (requires current TOTP)
        $currentOtp = $this->google2FA->getCurrentOtp($user->mfa_secret);

        $disableResponse = $this->postJson('/api/v1/mfa/disable', [
            'code' => $currentOtp,
        ]);

        $this->assertUnifiedApiResponse($disableResponse, 200);

        // Step 4: Verify MFA is disabled
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
            ->shouldReceive('isProviderSupportedForOrganization')
            ->with('google', $restrictedOrg->slug)
            ->andReturn(true);

        $googleResponse = $this->getJson('/api/v1/auth/social/google?organization='.$restrictedOrg->slug);
        $this->assertUnifiedApiResponse($googleResponse, 200);

        // Test disallowed provider (GitHub)
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupportedForOrganization')
            ->with('github', $restrictedOrg->slug)
            ->andReturn(false);

        $githubResponse = $this->getJson('/api/v1/auth/social/github?organization='.$restrictedOrg->slug);
        $githubResponse->assertStatus(400);
        $githubResponse->assertJson([
            'success' => false,
            'message' => 'Social provider not allowed for this organization',
        ]);
    }
}
