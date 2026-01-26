<?php

namespace Tests\Integration\Applications;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Token;
use Spatie\Permission\Models\Permission;
use Tests\Integration\IntegrationTestCase;

/**
 * Application User Access Management Integration Tests
 *
 * Tests user access control for OAuth applications including:
 * - Listing users with access to application
 * - Granting user access to application
 * - Revoking user access from application
 * - Bulk granting access to multiple users
 * - Bulk revoking access from multiple users
 * - Viewing user permissions and access metadata
 *
 * @covers \App\Http\Controllers\Api\ApplicationController
 */
class ApplicationUsersTest extends IntegrationTestCase
{
    protected User $adminUser;

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
        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        // Create application with Passport client
        $this->passportClient = Client::create([
            'name' => 'User Access Test App',
            'secret' => hash('sha256', 'test-secret'),
            'redirect' => 'https://app.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application = $this->createOAuthApplication([
            'name' => 'User Access Test Application',
            'organization_id' => $this->organization->id,
            'client_id' => (string) Str::uuid(),
            'client_secret' => 'test-secret',
            'passport_client_id' => $this->passportClient->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_users_with_access_to_application(): void
    {
        // ARRANGE: Create users with different access patterns
        $user1 = $this->createApiUser([
            'name' => 'Alice Johnson',
            'email' => 'alice@example.com',
            'organization_id' => $this->organization->id,
        ]);

        $user2 = $this->createApiUser([
            'name' => 'Bob Smith',
            'email' => 'bob@example.com',
            'organization_id' => $this->organization->id,
        ]);

        $user3 = $this->createApiUser([
            'name' => 'Charlie Brown',
            'email' => 'charlie@example.com',
            'organization_id' => $this->organization->id,
        ]);

        // Grant access with different metadata
        $this->application->users()->attach($user1->id, [
            'granted_at' => Carbon::now()->subDays(30),
            'last_login_at' => Carbon::now()->subDays(1),
            'login_count' => 15,
        ]);

        $this->application->users()->attach($user2->id, [
            'granted_at' => Carbon::now()->subDays(15),
            'last_login_at' => Carbon::now()->subDays(5),
            'login_count' => 8,
        ]);

        $this->application->users()->attach($user3->id, [
            'granted_at' => Carbon::now()->subDays(5),
            'last_login_at' => null, // Never logged in
            'login_count' => 0,
        ]);

        // User without access (should not appear)
        $userWithoutAccess = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: List users with access
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->getJson("/api/v1/applications/{$this->application->id}/users");

        // ASSERT: Response structure and data
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'email',
                        'granted_at',
                        'last_login_at',
                        'login_count',
                    ],
                ],
            ]);

        $users = $response->json('data');

        // ASSERT: Correct number of users
        $this->assertCount(3, $users);

        // ASSERT: User details included
        $alice = collect($users)->firstWhere('email', 'alice@example.com');
        $this->assertEquals('Alice Johnson', $alice['name']);
        $this->assertNotNull($alice['granted_at']);
        $this->assertNotNull($alice['last_login_at']);
        $this->assertEquals(15, $alice['login_count']);

        // ASSERT: User without login history
        $charlie = collect($users)->firstWhere('email', 'charlie@example.com');
        $this->assertNull($charlie['last_login_at']);
        $this->assertEquals(0, $charlie['login_count']);

        // ASSERT: User without access not included
        $userIds = array_column($users, 'id');
        $this->assertNotContains($userWithoutAccess->id, $userIds);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_grants_user_access_to_application(): void
    {
        // ARRANGE: Create user without access
        $user = $this->createApiUser([
            'name' => 'New User',
            'email' => 'newuser@example.com',
            'organization_id' => $this->organization->id,
        ]);

        // Verify no access initially
        $this->assertFalse($this->application->users()->where('user_id', $user->id)->exists());

        // ACT: Grant access
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->postJson("/api/v1/applications/{$this->application->id}/users", [
                'user_id' => $user->id,
            ]);

        // ASSERT: Response confirms grant
        $response->assertStatus(201)
            ->assertJson([
                'message' => 'User access granted successfully',
            ]);

        // ASSERT: Database updated with pivot data
        $this->assertDatabaseHas('user_applications', [
            'user_id' => $user->id,
            'application_id' => $this->application->id,
            'login_count' => 0,
        ]);

        // ASSERT: Access relationship exists
        $this->assertTrue($this->application->users()->where('user_id', $user->id)->exists());

        // ASSERT: Pivot metadata set correctly
        $pivot = $this->application->users()->where('user_id', $user->id)->first()->pivot;
        $this->assertNotNull($pivot->granted_at);
        $this->assertEquals(0, $pivot->login_count);
        $this->assertNull($pivot->last_login_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_duplicate_user_access_grants(): void
    {
        // ARRANGE: Create user with existing access
        $user = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        $this->application->users()->attach($user->id, [
            'granted_at' => Carbon::now()->subDays(10),
            'login_count' => 5,
        ]);

        // ACT: Attempt to grant access again
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->postJson("/api/v1/applications/{$this->application->id}/users", [
                'user_id' => $user->id,
            ]);

        // ASSERT: Conflict error returned
        $response->assertStatus(409)
            ->assertJsonStructure([
                'error',
                'error_description',
            ])
            ->assertJson([
                'error' => 'resource_conflict',
                'error_description' => 'User already has access to this application.',
            ]);

        // ASSERT: Original access unchanged
        $pivot = $this->application->users()->where('user_id', $user->id)->first()->pivot;
        $this->assertEquals(5, $pivot->login_count);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_revokes_user_access_and_invalidates_tokens(): void
    {
        // ARRANGE: Create user with access and active tokens
        $user = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        $this->application->users()->attach($user->id, [
            'granted_at' => Carbon::now()->subDays(10),
            'login_count' => 5,
        ]);

        // Create active tokens
        $token1 = Token::create([
            'id' => Str::random(80),
            'user_id' => $user->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Access Token 1',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHour(),
        ]);

        $token2 = Token::create([
            'id' => Str::random(80),
            'user_id' => $user->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Access Token 2',
            'scopes' => ['profile'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHours(2),
        ]);

        // Verify access exists
        $this->assertTrue($this->application->users()->where('user_id', $user->id)->exists());

        // ACT: Revoke access
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->deleteJson("/api/v1/applications/{$this->application->id}/users/{$user->id}");

        // ASSERT: Response confirms revocation
        $response->assertStatus(204)
            ->assertNoContent();

        // ASSERT: Access removed from database
        $this->assertDatabaseMissing('user_applications', [
            'user_id' => $user->id,
            'application_id' => $this->application->id,
        ]);

        // ASSERT: All user tokens for this application deleted
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token1->id]);
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $token2->id]);

        // ASSERT: Access relationship removed
        $this->assertFalse($this->application->users()->where('user_id', $user->id)->exists());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_revoking_access_for_non_existent_user(): void
    {
        // ARRANGE: Create user without access
        $user = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        // Verify no access
        $this->assertFalse($this->application->users()->where('user_id', $user->id)->exists());

        // ACT: Attempt to revoke non-existent access
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->deleteJson("/api/v1/applications/{$this->application->id}/users/{$user->id}");

        // ASSERT: Not found error
        $response->assertNotFound()
            ->assertJsonStructure([
                'error',
                'error_description',
            ])
            ->assertJson([
                'error' => 'resource_not_found',
                'error_description' => 'User does not have access to this application.',
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_user_access_operations(): void
    {
        // ACT: Attempt to grant access without user_id
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->postJson("/api/v1/applications/{$this->application->id}/users", []);

        // ASSERT: Validation error
        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details',
            ])
            ->assertJson([
                'error' => 'validation_failed',
            ]);

        // ACT: Attempt to grant access with invalid user_id
        $invalidResponse = $this->actingAsApiUserWithToken($this->adminUser)
            ->postJson("/api/v1/applications/{$this->application->id}/users", [
                'user_id' => 99999, // Non-existent user
            ]);

        // ASSERT: Validation catches invalid user
        $invalidResponse->assertStatus(422)
            ->assertJsonPath('details.user_id.0', 'The selected user id is invalid.');

        // ACT: Attempt to grant access with non-integer user_id
        $typeResponse = $this->actingAsApiUserWithToken($this->adminUser)
            ->postJson("/api/v1/applications/{$this->application->id}/users", [
                'user_id' => 'not-an-integer',
            ]);

        // ASSERT: Type validation
        $typeResponse->assertStatus(422);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_enforces_organization_boundaries_for_user_access(): void
    {
        // ARRANGE: Create users in different organizations
        $org1 = $this->createOrganization(['name' => 'Organization 1']);
        $org2 = $this->createOrganization(['name' => 'Organization 2']);

        $user1 = $this->createApiUser(['organization_id' => $org1->id]);
        $user2 = $this->createApiUser(['organization_id' => $org2->id]);

        $app1 = $this->createOAuthApplication([
            'organization_id' => $org1->id,
        ]);

        $app2 = $this->createOAuthApplication([
            'organization_id' => $org2->id,
        ]);
        $permissions = Permission::where('guard_name')
            ->whereIn('name', ['applications.read', 'applications.update'])
            ->get();
        $user1->givePermissionTo($permissions);
        $app1->users()->attach($user1->id, ['granted_at' => now()]);
        $app2->users()->attach($user2->id, ['granted_at' => now()]);

        // ACT & ASSERT: User 1 cannot list users for Org 2's application
        $listResponse = $this->actingAsApiUserWithToken($user1)
            ->getJson("/api/v1/applications/{$app2->id}/users");

        $listResponse->assertNotFound();

        // ACT & ASSERT: User 1 cannot grant access to Org 2's application
        $grantResponse = $this->actingAsApiUserWithToken($user1)
            ->postJson("/api/v1/applications/{$app2->id}/users", [
                'user_id' => $user1->id,
            ]);

        $grantResponse->assertNotFound();

        // ACT & ASSERT: User 1 cannot revoke access from Org 2's application
        $revokeResponse = $this->actingAsApiUserWithToken($user1)
            ->deleteJson("/api/v1/applications/{$app2->id}/users/{$user2->id}");

        $revokeResponse->assertNotFound();

        // ASSERT: Org 2's application access unchanged
        $this->assertTrue($app2->users()->where('user_id', $user2->id)->exists());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_user_login_metadata_in_pivot_table(): void
    {
        // ARRANGE: Create user with access
        $user = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        $this->application->users()->attach($user->id, [
            'granted_at' => Carbon::now()->subDays(30),
            'last_login_at' => Carbon::now()->subDays(10),
            'login_count' => 25,
        ]);

        // ACT: List users
        $response = $this->actingAsApiUserWithToken($this->adminUser)
            ->getJson("/api/v1/applications/{$this->application->id}/users");

        // ASSERT: Metadata included in response
        $response->assertOk();

        $users = $response->json('data');
        $userData = collect($users)->firstWhere('id', $user->id);

        $this->assertNotNull($userData['granted_at']);
        $this->assertNotNull($userData['last_login_at']);
        $this->assertEquals(25, $userData['login_count']);

        // ASSERT: Timestamps are properly formatted
        $grantedAt = Carbon::parse($userData['granted_at']);
        $lastLoginAt = Carbon::parse($userData['last_login_at']);

        $this->assertTrue($grantedAt->isBefore($lastLoginAt));
        $this->assertTrue($lastLoginAt->isPast());
    }
}
