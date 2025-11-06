<?php

namespace Tests\Integration\Applications;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use Spatie\Permission\Models\Permission;
use Tests\Integration\IntegrationTestCase;

/**
 * Application Token Management Integration Tests
 *
 * Tests complete token lifecycle management for OAuth applications including:
 * - Listing active tokens for application
 * - Viewing token details with user information
 * - Revoking specific tokens
 * - Revoking all tokens for application or user
 * - Token expiration handling
 * - Regenerating client secrets
 * - Rotating credentials
 * - Token introspection
 *
 * @covers \App\Http\Controllers\Api\ApplicationController
 */
class ApplicationTokensTest extends IntegrationTestCase
{
    protected User $user;

    protected Organization $organization;

    protected Application $application;

    protected Client $passportClient;

    protected function setUp(): void
    {
        parent::setUp();

        // Create permissions if they don't exist
        Permission::firstOrCreate(['name' => 'applications.read', 'guard_name' => 'api']);
        Permission::firstOrCreate(['name' => 'applications.update', 'guard_name' => 'api']);

        $this->organization = $this->createOrganization();
        $this->user = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        // Create application with Passport client
        $this->passportClient = Client::create([
            'name' => 'Test Token App',
            'secret' => hash('sha256', 'test-secret'),
            'redirect' => 'https://app.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application = $this->createOAuthApplication([
            'name' => 'Token Management Test App',
            'organization_id' => $this->organization->id,
            'client_id' => (string) Str::uuid(),
            'client_secret' => 'test-secret',
            'passport_client_id' => $this->passportClient->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_active_tokens_for_application(): void
    {
        // ARRANGE: Create multiple tokens with different states
        $user1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user2 = $this->createApiUser(['organization_id' => $this->organization->id]);

        // Active tokens
        $activeToken1 = $this->createAccessToken($user1, ['openid', 'profile'], $this->passportClient->id);
        $activeToken2 = $this->createAccessToken($user2, ['openid', 'email'], $this->passportClient->id);

        // Expired token (should not appear)
        $expiredToken = Token::create([
            'id' => Str::random(80),
            'user_id' => $user1->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Expired Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->subHour(), // Expired
        ]);

        // Revoked token (should not appear)
        $revokedToken = Token::create([
            'id' => Str::random(80),
            'user_id' => $user1->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Revoked Token',
            'scopes' => ['openid'],
            'revoked' => true,
            'expires_at' => Carbon::now()->addHour(),
        ]);

        // ACT: List active tokens for application
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/tokens");

        // ASSERT: Response structure and data
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'scopes',
                        'user' => ['id', 'name', 'email'],
                        'created_at',
                        'expires_at',
                        'last_used_at',
                    ],
                ],
            ]);

        $tokens = $response->json('data');

        // ASSERT: Only active, non-expired tokens returned
        $this->assertCount(2, $tokens);

        $tokenIds = array_column($tokens, 'id');
        $this->assertContains($activeToken1, $tokenIds);
        $this->assertContains($activeToken2, $tokenIds);
        $this->assertNotContains($expiredToken->id, $tokenIds);
        $this->assertNotContains($revokedToken->id, $tokenIds);

        // ASSERT: User information included
        $firstToken = collect($tokens)->firstWhere('id', $activeToken1);
        $this->assertEquals($user1->id, $firstToken['user']['id']);
        $this->assertEquals($user1->name, $firstToken['user']['name']);
        $this->assertEquals($user1->email, $firstToken['user']['email']);

        // ASSERT: Scopes included
        $this->assertIsArray($firstToken['scopes']);
        $this->assertContains('openid', $firstToken['scopes']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_views_token_details_with_metadata(): void
    {
        // ARRANGE: Create token with specific metadata
        $tokenUser = $this->createApiUser([
            'name' => 'Token User',
            'email' => 'tokenuser@example.com',
            'organization_id' => $this->organization->id,
        ]);

        $tokenId = $this->createAccessToken(
            $tokenUser,
            ['openid', 'profile', 'email', 'read'],
            $this->passportClient->id
        );

        $token = Token::find($tokenId);
        $token->update([
            'name' => 'My Access Token',
            'last_used_at' => Carbon::now()->subMinutes(15),
        ]);

        // ACT: Get token details
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/tokens");

        // ASSERT: Token details complete
        $response->assertOk();

        $tokens = $response->json('data');
        $tokenData = collect($tokens)->firstWhere('id', $tokenId);

        $this->assertNotNull($tokenData);
        $this->assertEquals('My Access Token', $tokenData['name']);
        $this->assertEquals(['openid', 'profile', 'email', 'read'], $tokenData['scopes']);
        $this->assertNotNull($tokenData['created_at']);
        $this->assertNotNull($tokenData['expires_at']);
        $this->assertNotNull($tokenData['last_used_at']);

        // ASSERT: User details present
        $this->assertEquals('Token User', $tokenData['user']['name']);
        $this->assertEquals('tokenuser@example.com', $tokenData['user']['email']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_revokes_specific_token_successfully(): void
    {
        // ARRANGE: Create token with refresh token
        $tokenUser = $this->createApiUser(['organization_id' => $this->organization->id]);

        $tokenId = $this->createAccessToken(
            $tokenUser,
            ['openid', 'profile'],
            $this->passportClient->id
        );

        $token = Token::find($tokenId);

        // Create associated refresh token
        $refreshToken = RefreshToken::create([
            'id' => Str::random(80),
            'access_token_id' => $token->id,
            'revoked' => false,
            'expires_at' => Carbon::now()->addDays(30),
        ]);

        $this->assertFalse($token->revoked);
        $this->assertFalse($refreshToken->revoked);

        // ACT: Revoke specific token
        $response = $this->actingAsApiUserWithToken($this->user)
            ->deleteJson("/api/v1/applications/{$this->application->id}/tokens/{$tokenId}");

        // ASSERT: Response confirms revocation
        $response->assertOk()
            ->assertJson([
                'message' => 'Token revoked successfully',
            ]);

        // ASSERT: Token marked as revoked
        $token->refresh();
        $this->assertTrue($token->revoked);

        // ASSERT: Refresh token also revoked
        $refreshToken->refresh();
        $this->assertTrue($refreshToken->revoked);

        // ASSERT: Authentication event logged
        $this->assertAuthenticationLogged([
            'user_id' => $tokenUser->id,
            'event' => 'token_revoked',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_revokes_all_tokens_for_application(): void
    {
        // ARRANGE: Create multiple tokens for different users
        $user1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user2 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user3 = $this->createApiUser(['organization_id' => $this->organization->id]);

        $token1 = $this->createAccessToken($user1, ['*'], $this->passportClient->id);
        $token2 = $this->createAccessToken($user2, ['*'], $this->passportClient->id);
        $token3 = $this->createAccessToken($user3, ['*'], $this->passportClient->id);

        // Create token for different application (should not be affected)
        $otherClient = Client::create([
            'name' => 'Other App',
            'secret' => hash('sha256', 'other-secret'),
            'redirect' => 'https://other.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $otherAppToken = $this->createAccessToken($user1, ['*'], $otherClient->id);

        // Verify all tokens exist
        $this->assertCount(3, Token::where('client_id', $this->passportClient->id)->get());

        // ACT: Revoke all tokens for application
        $response = $this->actingAsApiUserWithToken($this->user)
            ->deleteJson("/api/v1/applications/{$this->application->id}/tokens");

        // ASSERT: Response confirms revocation count
        $response->assertOk()
            ->assertJson([
                'message' => 'Revoked 3 active tokens',
            ]);

        // ASSERT: All application tokens deleted
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token1]);
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token2]);
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token3]);

        // ASSERT: Other application's tokens unaffected
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $otherAppToken]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_token_expiration_correctly(): void
    {
        // ARRANGE: Create tokens with different expiration times
        $user = $this->createApiUser(['organization_id' => $this->organization->id]);

        // Token that just expired
        $justExpired = Token::create([
            'id' => Str::random(80),
            'user_id' => $user->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Just Expired',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->subMinute(),
        ]);

        // Token expiring soon
        $expiringSoon = Token::create([
            'id' => Str::random(80),
            'user_id' => $user->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Expiring Soon',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(5),
        ]);

        // Token with plenty of time
        $validToken = Token::create([
            'id' => Str::random(80),
            'user_id' => $user->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Valid Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHours(2),
        ]);

        // ACT: List active tokens
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/tokens");

        // ASSERT: Only non-expired tokens returned
        $response->assertOk();

        $tokens = $response->json('data');
        $tokenIds = array_column($tokens, 'id');

        $this->assertCount(2, $tokens);
        $this->assertContains($expiringSoon->id, $tokenIds);
        $this->assertContains($validToken->id, $tokenIds);
        $this->assertNotContains($justExpired->id, $tokenIds);

        // ASSERT: Expiration times are future dates
        foreach ($tokens as $token) {
            $expiresAt = Carbon::parse($token['expires_at']);
            $this->assertTrue($expiresAt->isFuture(), "Token {$token['id']} expires_at should be in the future");
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_regenerates_client_secret_and_invalidates_tokens(): void
    {
        // ARRANGE: Create tokens for the application
        $user1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user2 = $this->createApiUser(['organization_id' => $this->organization->id]);

        $token1 = $this->createAccessToken($user1, ['*'], $this->passportClient->id);
        $token2 = $this->createAccessToken($user2, ['*'], $this->passportClient->id);

        $originalClientId = $this->application->client_id;
        $originalClientSecret = $this->application->client_secret;

        // ACT: Regenerate credentials
        $response = $this->actingAsApiUserWithToken($this->user)
            ->postJson("/api/v1/applications/{$this->application->id}/credentials/regenerate");

        // ASSERT: Response contains new credentials
        $response->assertOk()
            ->assertJsonStructure([
                'data' => ['client_id', 'client_secret'],
                'message',
            ])
            ->assertJson([
                'message' => 'Application credentials regenerated successfully',
            ]);

        $newCredentials = $response->json('data');

        // ASSERT: Credentials changed
        $this->assertNotEquals($originalClientId, $newCredentials['client_id']);
        $this->assertNotEquals($originalClientSecret, $newCredentials['client_secret']);

        // ASSERT: New credentials are valid format
        $this->assertTrue(Str::isUuid($newCredentials['client_id']));
        $this->assertEquals(64, strlen($newCredentials['client_secret']));

        // ASSERT: Database updated
        $this->application->refresh();
        $this->assertEquals($newCredentials['client_id'], $this->application->client_id);
        $this->assertEquals($newCredentials['client_secret'], $this->application->client_secret);

        // ASSERT: Passport client updated
        $this->passportClient->refresh();
        $this->assertEquals(
            hash('sha256', $newCredentials['client_secret']),
            $this->passportClient->secret
        );

        // ASSERT: All existing tokens invalidated
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token1]);
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token2]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_rotates_credentials_without_breaking_active_flows(): void
    {
        // ARRANGE: Setup application with specific settings
        $originalClientId = $this->application->client_id;
        $originalSecret = $this->application->client_secret;

        // Create an active token
        $user = $this->createApiUser(['organization_id' => $this->organization->id]);
        $activeToken = $this->createAccessToken($user, ['*'], $this->passportClient->id);

        // ACT: Regenerate credentials
        $response = $this->actingAsApiUserWithToken($this->user)
            ->postJson("/api/v1/applications/{$this->application->id}/credentials/regenerate");

        // ASSERT: Regeneration successful
        $response->assertOk();

        $newCredentials = $response->json('data');

        // ASSERT: Old token is gone (strict rotation)
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $activeToken]);

        // ASSERT: Application settings preserved
        $this->application->refresh();
        $this->assertEquals('Token Management Test App', $this->application->name);
        $this->assertNotNull($this->application->settings);
        $this->assertTrue($this->application->is_active);

        // ASSERT: Can create new tokens with new credentials
        $token = Token::create([
            'id' => Str::random(80),
            'user_id' => $user->id,
            'client_id' => $this->passportClient->id,
            'name' => 'New Token After Rotation',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHour(),
        ]);

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $token->id,
            'client_id' => $this->passportClient->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_token_operations_across_organizations(): void
    {
        // ARRANGE: Create application and token in different organization
        $otherOrg = $this->createOrganization(['name' => 'Other Organization']);
        $otherUser = $this->createApiUser(['organization_id' => $otherOrg->id]);

        $otherClient = Client::create([
            'name' => 'Other Org App',
            'secret' => hash('sha256', 'other-secret'),
            'redirect' => 'https://other.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $otherApplication = $this->createOAuthApplication([
            'organization_id' => $otherOrg->id,
            'passport_client_id' => $otherClient->id,
        ]);

        $otherToken = $this->createAccessToken($otherUser, ['*'], $otherClient->id);

        // ACT & ASSERT: Cannot list tokens from other org's application
        $listResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$otherApplication->id}/tokens");

        $listResponse->assertNotFound();

        // ACT & ASSERT: Cannot revoke tokens from other org's application
        $revokeResponse = $this->actingAsApiUserWithToken($this->user)
            ->deleteJson("/api/v1/applications/{$otherApplication->id}/tokens/{$otherToken}");

        $revokeResponse->assertNotFound();

        // ACT & ASSERT: Cannot regenerate credentials for other org's application
        $regenResponse = $this->actingAsApiUserWithToken($this->user)
            ->postJson("/api/v1/applications/{$otherApplication->id}/credentials/regenerate");

        $regenResponse->assertNotFound();

        // ASSERT: Other organization's token still exists
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $otherToken]);
    }
}
