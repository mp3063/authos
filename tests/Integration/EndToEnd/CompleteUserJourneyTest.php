<?php

namespace Tests\Integration\EndToEnd;

use App\Models\AuthenticationLog;
use App\Models\User;
use Laravel\Passport\Token;

/**
 * End-to-End test demonstrating complete user journey scenarios.
 *
 * This test class serves as an example of how to use the EndToEndTestCase
 * infrastructure to test complex user workflows from registration to
 * application usage.
 */
class CompleteUserJourneyTest extends EndToEndTestCase
{
    /**
     * Test complete user registration and onboarding flow
     */
    public function test_complete_user_registration_flow(): void
    {
        // Step 1: User attempts registration
        $registrationData = [
            'name' => 'John Doe',
            'email' => 'john.doe@example.com',
            'password' => 'SecurePassword123!',
            'password_confirmation' => 'SecurePassword123!',
            'organization_slug' => $this->defaultOrganization->slug,
            'profile' => [
                'bio' => 'Software developer passionate about authentication',
                'location' => 'San Francisco, CA',
                'website' => 'https://johndoe.dev',
            ],
            'terms_accepted' => true,
        ];

        $response = $this->postJson('/api/v1/auth/register', $registrationData);

        // Assert successful registration with legacy format
        $response->assertStatus(201);
        $response->assertJsonStructure([
            'user' => [
                'id',
                'name',
                'email',
                'organization_id',
                'profile',
                'is_active',
            ],
            'token' => [
                'access_token',
                'token_type',
                'expires_at',
            ],
            'scopes',
        ]);

        // Verify user was created in database
        $user = User::where('email', 'john.doe@example.com')->first();
        $this->assertNotNull($user);
        $this->assertEquals($this->defaultOrganization->id, $user->organization_id);
        $this->assertTrue($user->hasRole('User'));

        // Verify authentication log was created
        $this->assertAuditLogExists($user, 'user_registered');

        // Step 2: User logs in with credentials
        $loginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => 'john.doe@example.com',
            'password' => 'SecurePassword123!',
        ]);

        $loginResponse->assertStatus(200);
        $this->assertAuditLogExists($user, 'login_success');

        // Step 3: User accesses protected profile endpoint using Passport actingAs
        $this->actingAsApiUser($user);
        $profileResponse = $this->getJson('/api/v1/auth/user');

        $profileResponse->assertStatus(200);
        $profileResponse->assertJson([
            'id' => $user->id,
            'email' => 'john.doe@example.com',
        ]);

        // Step 4: User updates their profile
        $this->actingAsApiUser($user);
        $updateResponse = $this->putJson('/api/v1/profile', [
            'name' => 'John Smith',
            'profile' => [
                'bio' => 'Senior software developer',
                'location' => 'Los Angeles, CA',
            ],
        ]);

        $updateResponse->assertStatus(200);

        // Verify profile was updated
        $user->refresh();
        $this->assertEquals('John Smith', $user->name);
        $this->assertEquals('Senior software developer', $user->profile['bio']);
    }

    /**
     * Test complete OAuth application authorization flow
     */
    public function test_complete_oauth_authorization_flow(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Step 1: Client requests authorization
        $authParams = [
            'response_type' => 'code',
            'client_id' => $this->oauthClient->id,
            'redirect_uri' => $this->oauthClient->redirect,
            'scope' => 'openid profile email',
            'state' => 'test_state_123',
            'code_challenge' => 'test_challenge',
            'code_challenge_method' => 'S256',
        ];

        $authResponse = $this->get('/oauth/authorize?'.http_build_query($authParams));
        $authResponse->assertStatus(200); // Authorization page displayed

        // Step 2: User approves authorization (simulate form submission)
        $approvalResponse = $this->post('/oauth/authorize', array_merge($authParams, [
            'approve' => 'Approve',
        ]));

        // Should redirect with authorization code
        $approvalResponse->assertRedirect();
        $redirectUrl = $approvalResponse->headers->get('Location');
        $this->assertStringContains('code=', $redirectUrl);

        // Extract authorization code from redirect
        parse_str(parse_url($redirectUrl, PHP_URL_QUERY), $queryParams);
        $authCode = $queryParams['code'];

        // Step 3: Client exchanges code for tokens
        $tokenResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
            'code' => $authCode,
            'redirect_uri' => $this->oauthClient->redirect,
            'code_verifier' => 'test_verifier',
        ]);

        $tokenResponse->assertStatus(200);
        $tokenData = $tokenResponse->json();

        $this->assertArrayHasKey('access_token', $tokenData);
        $this->assertArrayHasKey('refresh_token', $tokenData);
        $this->assertArrayHasKey('expires_in', $tokenData);
        $this->assertEquals('Bearer', $tokenData['token_type']);

        // Step 4: Use access token to access user info
        $userInfoResponse = $this->getJson('/oauth/userinfo', [
            'Authorization' => 'Bearer '.$tokenData['access_token'],
        ]);

        $userInfoResponse->assertStatus(200);
        $userInfoResponse->assertJson([
            'sub' => (string) $user->id,
            'email' => $user->email,
            'name' => $user->name,
        ]);

        // Step 5: Use refresh token to get new access token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokenData['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
        ]);

        $refreshResponse->assertStatus(200);
        $newTokenData = $refreshResponse->json();

        $this->assertArrayHasKey('access_token', $newTokenData);
        $this->assertNotEquals($tokenData['access_token'], $newTokenData['access_token']);

        // Step 6: Verify old refresh token is invalidated (refresh token rotation)
        $oldRefreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokenData['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
        ]);

        $oldRefreshResponse->assertStatus(401); // Should fail with old refresh token
    }

    /**
     * Test complete social authentication flow
     */
    public function test_complete_social_authentication_flow(): void
    {
        $socialUser = $this->mockSuccessfulSocialAuth('google');

        // Step 1: Client requests social authentication redirect
        $providersResponse = $this->getJson('/api/v1/auth/social/providers');
        $this->assertUnifiedApiResponse($providersResponse, 200);

        $redirectResponse = $this->getJson('/api/v1/auth/social/google');
        $this->assertUnifiedApiResponse($redirectResponse, 200);

        $redirectResponse->assertJsonStructure([
            'success',
            'data' => [
                'redirect_url',
                'provider',
            ],
        ]);

        // Step 2: User completes OAuth flow with Google (mocked)
        $callbackResponse = $this->getJson('/api/v1/auth/social/google/callback');
        $this->assertUnifiedApiResponse($callbackResponse, 200);

        $callbackResponse->assertJsonStructure([
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
                ],
            ],
        ]);

        // Verify authentication log for social login
        $this->assertAuditLogExists($socialUser, 'social_login_success');

        // Step 3: User accesses protected resources with social account
        $this->actingAsApiUser($socialUser);
        $profileResponse = $this->getJson('/api/v1/auth/user');
        $this->assertUnifiedApiResponse($profileResponse, 200);

        $profileResponse->assertJson([
            'provider' => 'google',
            'is_social_user' => true,
        ]);

        // Step 4: User sets password to enable password login
        $passwordResponse = $this->putJson('/api/v1/profile/password', [
            'password' => 'NewSecurePassword123!',
            'password_confirmation' => 'NewSecurePassword123!',
        ]);

        $this->assertUnifiedApiResponse($passwordResponse, 200);

        // Step 5: User can now login with password
        $passwordLoginResponse = $this->postJson('/api/v1/auth/login', [
            'email' => $socialUser->email,
            'password' => 'NewSecurePassword123!',
        ]);

        $this->assertUnifiedApiResponse($passwordLoginResponse, 200);

        // Step 6: User unlinks social account
        $unlinkResponse = $this->deleteJson('/api/v1/auth/social/unlink');
        $this->assertUnifiedApiResponse($unlinkResponse, 200);

        // Verify social data was cleared
        $socialUser->refresh();
        $this->assertNull($socialUser->provider);
        $this->assertNull($socialUser->provider_id);
    }

    /**
     * Test multi-organization data isolation during user workflows
     */
    public function test_multi_organization_data_isolation(): void
    {
        $organizations = $this->setupMultiOrganizationScenario();

        foreach ($organizations as $index => $orgData) {
            $user = $orgData['users'][0];
            $organization = $orgData['organization'];

            // Test that user can only access their organization's data
            $this->assertOrganizationDataIsolation($user, $organization);

            // Test cross-organization access is prevented
            $otherOrgIndex = ($index + 1) % count($organizations);
            $otherOrg = $organizations[$otherOrgIndex]['organization'];

            $this->actingAs($user, 'api');

            // Attempt to access other organization's user
            $otherUser = $organizations[$otherOrgIndex]['users'][0];
            $response = $this->getJson("/api/v1/users/{$otherUser->id}");
            $response->assertStatus(404); // Should not find user from other org

            // Attempt to access other organization's application
            $otherApp = $organizations[$otherOrgIndex]['application'];
            $response = $this->getJson("/api/v1/applications/{$otherApp->id}");
            $response->assertStatus(404); // Should not find app from other org
        }
    }

    /**
     * Test token expiration and refresh scenarios
     */
    public function test_token_expiration_and_refresh_flow(): void
    {
        $user = $this->actingAsTestUser('regular');

        // Create a short-lived token
        $token = $user->createToken('Test Token', ['*'], now()->addMinutes(5));
        $accessToken = $token->accessToken;

        // Verify token works initially
        $response = $this->getJson('/api/v1/auth/user', [
            'Authorization' => 'Bearer '.$accessToken,
        ]);
        $this->assertUnifiedApiResponse($response, 200);

        // Travel to future to expire token
        $this->travelToFuture(10); // 10 minutes in future

        // Verify token is now expired
        $response = $this->getJson('/api/v1/auth/user', [
            'Authorization' => 'Bearer '.$accessToken,
        ]);
        $response->assertStatus(401);

        // Return to present
        $this->returnToPresent();

        // Test refresh token flow with OAuth tokens
        $oauthTokens = $this->performOAuthFlow($user, $this->oauthClient);

        // Use refresh token to get new access token
        $refreshResponse = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $oauthTokens['refresh_token'],
            'client_id' => $this->oauthClient->id,
            'client_secret' => $this->oauthClient->secret,
        ]);

        $refreshResponse->assertStatus(200);
        $newTokens = $refreshResponse->json();

        // Verify new token works
        $response = $this->getJson('/oauth/userinfo', [
            'Authorization' => 'Bearer '.$newTokens['access_token'],
        ]);
        $response->assertStatus(200);
    }

    /**
     * Test high-load scenario with concurrent requests
     */
    public function test_high_load_concurrent_requests(): void
    {
        // Create multiple users for load testing
        $users = [];
        for ($i = 0; $i < 10; $i++) {
            $users[] = $this->createUser([
                'name' => "Load Test User {$i}",
                'email' => "loadtest{$i}@example.com",
                'organization_id' => $this->defaultOrganization->id,
            ], 'User');
        }

        // Simulate concurrent authentication requests
        $responses = [];
        foreach ($users as $user) {
            $this->actingAsApiUser($user);
            $responses[] = $this->getJson('/api/v1/auth/user');
        }

        // Verify all requests succeeded
        foreach ($responses as $response) {
            $this->assertUnifiedApiResponse($response, 200);
        }

        // Simulate high load on public endpoints
        $loadResponses = $this->simulateHighLoad(25);

        // Verify system handled load gracefully
        $successCount = 0;
        foreach ($loadResponses as $response) {
            if ($response->status() === 200) {
                $successCount++;
            }
        }

        // At least 80% should succeed under load
        $this->assertGreaterThanOrEqual(20, $successCount);
    }

    /**
     * Test complete security audit trail
     */
    public function test_complete_security_audit_trail(): void
    {
        $user = $this->createUser([
            'name' => 'Audit Test User',
            'email' => 'audit@example.com',
            'organization_id' => $this->defaultOrganization->id,
        ], 'User');

        // Clear existing logs
        AuthenticationLog::where('user_id', $user->id)->delete();

        // 1. Registration event
        $this->createAuthenticationLog($user, 'user_registered');

        // 2. Login events
        $this->actingAsApiUser($user);
        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        // 3. Profile access
        $this->getJson('/api/v1/auth/user');

        // 4. Failed login attempt
        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'wrong_password',
        ]);

        // 5. Password change
        $this->putJson('/api/v1/profile/password', [
            'current_password' => 'password',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        // 6. Logout
        $this->postJson('/api/v1/auth/logout');

        // Verify comprehensive audit trail
        $logs = AuthenticationLog::where('user_id', $user->id)
            ->orderBy('created_at')
            ->get();

        $this->assertGreaterThanOrEqual(4, $logs->count());

        // Verify specific events are logged
        $events = $logs->pluck('event')->toArray();
        $this->assertContains('user_registered', $events);
        $this->assertContains('login_failed', $events);
        $this->assertContains('logout', $events);

        // Test audit log access for organization admin
        $this->actingAs($this->organizationAdmin, 'api');
        $auditResponse = $this->getJson('/api/v1/users/'.$user->id.'/logs');
        $this->assertUnifiedApiResponse($auditResponse, 200);

        $auditResponse->assertJsonStructure([
            'success',
            'data' => [
                'data' => [
                    '*' => [
                        'id',
                        'event',
                        'ip_address',
                        'user_agent',
                        'success',
                        'created_at',
                    ],
                ],
                'meta',
            ],
        ]);
    }
}
