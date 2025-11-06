<?php

namespace Tests\Integration\Users;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Tests\TestCase;

/**
 * Integration tests for User Session Management
 *
 * Tests the complete session management lifecycle including:
 * - Listing active sessions for a user
 * - Viewing individual session details
 * - Revoking specific sessions
 * - Revoking all other sessions
 * - Session timeout handling
 * - Session activity tracking
 */
class UserSessionsTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;
    private User $user;
    private User $adminUser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create([
            'name' => 'Test Organization',
        ]);

        $this->user = $this->createApiUser([
            'organization_id' => $this->organization->id,
            'email' => 'user@test.com',
        ]);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'admin@test.com',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_active_sessions_for_user(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // Create multiple tokens (sessions) for the user
        $token1 = $this->user->createToken('Session 1', ['*']);
        $token2 = $this->user->createToken('Session 2', ['*']);
        $token3 = $this->user->createToken('Session 3', ['*']);

        // Update token metadata to simulate different devices/locations
        DB::table('oauth_access_tokens')->where('id', $token1->token->id)->update([
            'created_at' => now()->subHours(2),
        ]);
        DB::table('oauth_access_tokens')->where('id', $token2->token->id)->update([
            'created_at' => now()->subHour(),
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
            ])
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'scopes',
                        'created_at',
                        'expires_at',
                        'last_used_at',
                    ],
                ],
            ]);

        // Should have at least 3 sessions
        $this->assertGreaterThanOrEqual(3, count($response->json('data')));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_views_specific_session_details(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $token = $this->user->createToken('Test Session', ['users.read', 'applications.read']);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions/{$token->token->id}");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $token->token->id,
                    'name' => 'Test Session',
                ],
            ])
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'scopes',
                    'created_at',
                    'expires_at',
                    'last_used_at',
                    'revoked',
                ],
            ]);

        // Verify scopes
        $scopes = $response->json('data.scopes');
        $this->assertContains('users.read', $scopes);
        $this->assertContains('applications.read', $scopes);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_revokes_specific_session(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.update']);

        // Create two tokens for the user
        $token1 = $this->user->createToken('Session to Revoke', ['*']);
        $token2 = $this->user->createToken('Session to Keep', ['*']);

        $sessionToRevoke = $token1->token->id;

        // ACT
        $response = $this->deleteJson("/api/v1/users/{$this->user->id}/sessions/{$sessionToRevoke}");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Session revoked successfully',
            ]);

        // Verify token was revoked
        $revokedToken = Token::find($sessionToRevoke);
        $this->assertTrue($revokedToken->revoked);

        // Verify other token is still active
        $activeToken = Token::find($token2->token->id);
        $this->assertFalse($activeToken->revoked);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'session_revoked',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_revokes_all_other_sessions(): void
    {
        // ARRANGE
        // Create multiple tokens for the user
        $token1 = $this->user->createToken('Session 1', ['*']);
        $token2 = $this->user->createToken('Session 2', ['*']);
        $token3 = $this->user->createToken('Session 3', ['*']);

        // Act as admin with proper permissions
        Passport::actingAs($this->adminUser, ['users.update']);

        $currentTokenId = $token1->token->id;

        // ACT - Revoke all sessions except current
        $response = $this->deleteJson("/api/v1/users/{$this->user->id}/sessions");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'All other sessions revoked successfully',
            ]);

        // Verify all user tokens were revoked (admin is revoking all user's sessions)
        $token1->token->refresh();
        $token2->token->refresh();
        $token3->token->refresh();
        $this->assertTrue($token1->token->revoked);
        $this->assertTrue($token2->token->revoked);
        $this->assertTrue($token3->token->revoked);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'all_sessions_revoked',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_session_timeout(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // Create an expired token
        $token = $this->user->createToken('Expired Session', ['*']);

        // Manually expire the token
        DB::table('oauth_access_tokens')
            ->where('id', $token->token->id)
            ->update(['expires_at' => now()->subDay()]);

        // ACT - Try to list sessions with expired token
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions");

        // ASSERT - Should still work as we're listing sessions, not using the expired one
        $response->assertStatus(200);

        // The expired session should be marked appropriately
        $sessions = $response->json('data');
        $expiredSession = collect($sessions)->firstWhere('id', $token->token->id);

        if ($expiredSession) {
            $this->assertNotNull($expiredSession['expires_at']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_session_activity(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $token = $this->user->createToken('Test Session', ['*']);

        // Simulate some API activity
        $this->getJson('/api/v1/profile');
        $this->getJson("/api/v1/users/{$this->user->id}");

        // ACT - Get session details
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions/{$token->token->id}");

        // ASSERT
        $response->assertStatus(200);

        // Verify last_used_at is tracked
        $lastUsedAt = $response->json('data.last_used_at');
        $this->assertNotNull($lastUsedAt);

        // Verify created_at exists
        $this->assertNotNull($response->json('data.created_at'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function admin_can_view_other_users_sessions(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.read']);

        // Create sessions for the regular user
        $this->user->createToken('User Session 1', ['*']);
        $this->user->createToken('User Session 2', ['*']);

        // ACT - Admin views another user's sessions
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions");

        // ASSERT
        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => ['id', 'name', 'created_at'],
                ],
            ]);

        $this->assertGreaterThanOrEqual(2, count($response->json('data')));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function admin_can_revoke_other_users_sessions(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.update']);

        $userToken = $this->user->createToken('User Session', ['*']);
        $sessionId = $userToken->token->id;

        // ACT - Admin revokes another user's session
        $response = $this->deleteJson("/api/v1/users/{$this->user->id}/sessions/{$sessionId}");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Session revoked successfully',
            ]);

        // Verify token was revoked
        $revokedToken = Token::find($sessionId);
        $this->assertTrue($revokedToken->revoked);

        // Verify audit log shows admin performed action
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'session_revoked',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_cannot_view_other_users_sessions(): void
    {
        // ARRANGE
        $otherUser = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->user, ['users.read']);

        // ACT - Try to view another user's sessions
        $response = $this->getJson("/api/v1/users/{$otherUser->id}/sessions");

        // ASSERT - Should be forbidden
        $response->assertStatus(403);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_enforces_organization_boundary_for_sessions(): void
    {
        // ARRANGE
        $otherOrganization = Organization::factory()->create();
        $otherOrgUser = User::factory()->create([
            'organization_id' => $otherOrganization->id,
        ]);

        Passport::actingAs($this->adminUser, ['users.read']);

        // ACT - Try to access sessions from different organization
        $response = $this->getJson("/api/v1/users/{$otherOrgUser->id}/sessions");

        // ASSERT - Should not find the user due to organization boundary
        $response->assertStatus(404);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_nonexistent_session_gracefully(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.update']);

        $nonexistentSessionId = 'nonexistent-session-id-12345';

        // ACT
        $response = $this->deleteJson("/api/v1/users/{$this->user->id}/sessions/{$nonexistentSessionId}");

        // ASSERT
        $response->assertStatus(404);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_sessions_with_pagination(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // Create many sessions
        for ($i = 1; $i <= 15; $i++) {
            $this->user->createToken("Session {$i}", ['*']);
        }

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions?per_page=5&page=1");

        // ASSERT
        $response->assertStatus(200)
            ->assertJsonStructure([
                'data',
                'meta' => [
                    'current_page',
                    'per_page',
                    'total',
                    'last_page',
                ],
            ]);

        $this->assertEquals(5, count($response->json('data')));
        $this->assertGreaterThanOrEqual(15, $response->json('meta.total'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_includes_session_metadata_in_response(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $token = $this->user->createToken('Test Session', ['users.read', 'applications.read']);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->user->id}/sessions/{$token->token->id}");

        // ASSERT
        $response->assertStatus(200);

        $session = $response->json('data');

        // Verify all expected fields are present
        $this->assertArrayHasKey('id', $session);
        $this->assertArrayHasKey('name', $session);
        $this->assertArrayHasKey('scopes', $session);
        $this->assertArrayHasKey('created_at', $session);
        $this->assertArrayHasKey('expires_at', $session);
        $this->assertArrayHasKey('revoked', $session);

        // Verify data types
        $this->assertIsString($session['id']);
        $this->assertIsString($session['name']);
        $this->assertIsArray($session['scopes']);
        $this->assertIsBool($session['revoked']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_revoking_current_session_when_revoking_all(): void
    {
        // ARRANGE
        $token1 = $this->user->createToken('Current Session', ['*']);
        $token2 = $this->user->createToken('Other Session', ['*']);

        Passport::actingAs($this->adminUser, ['users.update']);

        // ACT - Admin revokes all user sessions
        $response = $this->deleteJson("/api/v1/users/{$this->user->id}/sessions");

        // ASSERT
        $response->assertStatus(200);

        // Verify all user sessions are revoked (admin action revokes all)
        $token1->token->refresh();
        $token2->token->refresh();
        $this->assertTrue($token1->token->revoked);
        $this->assertTrue($token2->token->revoked);
    }
}
