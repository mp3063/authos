<?php

namespace Tests\Integration\Models;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * SSO Session Model Lifecycle Integration Tests
 *
 * Tests the complete lifecycle of SSO Session models including:
 * - Auto-generation of session and refresh tokens
 * - Activity tracking (last_activity_at updates)
 * - Session expiration logic
 * - Logout and revocation handling
 * - External session ID tracking
 * - Metadata handling (JSON cast)
 * - Session cleanup on user deletion
 *
 * @covers \App\Models\SSOSession
 */
class SsoSessionLifecycleTest extends IntegrationTestCase
{
    protected Organization $organization;

    protected User $user;

    protected Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->user = $this->createUser([
            'organization_id' => $this->organization->id,
        ]);
        $this->application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_auto_generates_session_token_on_create(): void
    {
        // ARRANGE: Prepare session data without session_token
        $data = [
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ];

        // ACT: Create session without providing session_token
        $session = SSOSession::create($data);

        // ASSERT: session_token should be auto-generated as 64-char random string
        $this->assertNotNull($session->session_token);
        $this->assertEquals(64, strlen($session->session_token));
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9]+$/', $session->session_token);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_auto_generates_refresh_token_on_create(): void
    {
        // ARRANGE: Prepare session data without refresh_token
        $data = [
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ];

        // ACT: Create session
        $session = SSOSession::create($data);

        // ASSERT: refresh_token should be auto-generated as 64-char random string
        $this->assertNotNull($session->refresh_token);
        $this->assertEquals(64, strlen($session->refresh_token));
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9]+$/', $session->refresh_token);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_sets_last_activity_at_on_create(): void
    {
        // ACT: Create session without providing last_activity_at
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        // ASSERT: last_activity_at should be set to current timestamp
        $this->assertNotNull($session->last_activity_at);
        // Check that it was set within the last few seconds
        $this->assertTrue($session->last_activity_at->diffInSeconds(now()) < 5);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_respects_provided_session_token_on_create(): void
    {
        // ARRANGE: Prepare session data with custom session_token
        $customToken = 'custom-token-'.str_repeat('x', 51);
        $data = [
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'session_token' => $customToken,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ];

        // ACT: Create session with custom session_token
        $session = SSOSession::create($data);

        // ASSERT: Should use provided session_token
        $this->assertEquals($customToken, $session->session_token);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_last_activity_at_on_activity_update(): void
    {
        // ARRANGE: Create session with old activity timestamp
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
            'last_activity_at' => now()->subMinutes(30),
        ]);

        $oldActivity = $session->last_activity_at;

        // Wait a brief moment to ensure timestamp difference
        sleep(1);

        // ACT: Update last activity
        $session->updateLastActivity();
        $session->refresh();

        // ASSERT: last_activity_at should be updated to more recent time
        $this->assertTrue($session->last_activity_at->greaterThan($oldActivity));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_correctly_identifies_expired_sessions(): void
    {
        // ARRANGE: Create expired session
        $expiredSession = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->subHour(),
        ]);

        // Create active session
        $activeSession = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.2',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        // ACT & ASSERT: Check expiration status
        $this->assertTrue($expiredSession->isExpired());
        $this->assertFalse($activeSession->isExpired());
        $this->assertFalse($expiredSession->isActive());
        $this->assertTrue($activeSession->isActive());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_logout_correctly(): void
    {
        // ARRANGE: Create active session
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        $this->assertNull($session->logged_out_at);
        $this->assertTrue($session->isActive());

        // ACT: Logout the session
        $session->logout($this->user);
        $session->refresh();

        // ASSERT: Session should be marked as logged out
        $this->assertNotNull($session->logged_out_at);
        $this->assertEquals($this->user->id, $session->logged_out_by);
        $this->assertFalse($session->isActive());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_external_session_id(): void
    {
        // ARRANGE: Create session with external session ID
        $externalId = 'ext-session-'.uniqid();

        // ACT: Create session
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'external_session_id' => $externalId,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        // ASSERT: External session ID should be tracked
        $this->assertEquals($externalId, $session->external_session_id);
        $this->assertDatabaseHas('sso_sessions', [
            'id' => $session->id,
            'external_session_id' => $externalId,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_metadata_as_json(): void
    {
        // ARRANGE: Prepare metadata
        $metadata = [
            'device' => 'iPhone 13',
            'browser' => 'Safari',
            'os' => 'iOS 15',
            'location' => [
                'country' => 'US',
                'city' => 'New York',
                'timezone' => 'America/New_York',
            ],
        ];

        // ACT: Create session with metadata
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
            'metadata' => $metadata,
        ]);

        // ASSERT: Metadata should be stored and retrieved as array
        $session->refresh();
        $this->assertEquals($metadata, $session->metadata);
        $this->assertEquals('iPhone 13', $session->metadata['device']);
        $this->assertEquals('New York', $session->metadata['location']['city']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_extends_session_expiry_and_updates_activity(): void
    {
        // ARRANGE: Create session
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHour(),
            'last_activity_at' => now()->subMinutes(30),
        ]);

        $originalExpiry = $session->expires_at;
        $originalActivity = $session->last_activity_at;

        // Wait a brief moment
        sleep(1);

        // ACT: Extend session by 1 hour
        $session->extendSession(3600);
        $session->refresh();

        // ASSERT: Both expiry and activity should be updated
        $this->assertTrue($session->expires_at->greaterThan($originalExpiry));
        $this->assertTrue($session->last_activity_at->greaterThan($originalActivity));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_generates_new_session_token_on_regeneration(): void
    {
        // ARRANGE: Create session
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        $originalToken = $session->session_token;

        // ACT: Regenerate session token
        $newToken = $session->generateNewSessionToken();
        $session->refresh();

        // ASSERT: Token should be different
        $this->assertNotEquals($originalToken, $newToken);
        $this->assertEquals($newToken, $session->session_token);
        $this->assertEquals(64, strlen($newToken));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_generates_new_refresh_token_on_regeneration(): void
    {
        // ARRANGE: Create session
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        $originalToken = $session->refresh_token;

        // ACT: Regenerate refresh token using the direct method
        $newToken = $session->generateNewRefreshToken();

        // ASSERT: Token should be different and saved to database
        $this->assertNotEquals($originalToken, $newToken);
        $this->assertEquals(64, strlen($newToken));

        // Refresh from database to verify persistence
        $session = $session->fresh();
        $this->assertEquals($newToken, $session->refresh_token);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_finds_session_by_session_token(): void
    {
        // ARRANGE: Create session
        $session = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        // ACT: Find session by token
        $foundSession = SSOSession::findBySessionToken($session->session_token);

        // ASSERT: Should find the correct session
        $this->assertNotNull($foundSession);
        $this->assertEquals($session->id, $foundSession->id);
        $this->assertEquals($session->session_token, $foundSession->session_token);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_generates_unique_tokens_for_multiple_sessions(): void
    {
        // ARRANGE & ACT: Create multiple sessions
        $session1 = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'expires_at' => now()->addHours(2),
        ]);

        $session2 = SSOSession::create([
            'user_id' => $this->user->id,
            'application_id' => $this->application->id,
            'ip_address' => '192.168.1.2',
            'user_agent' => 'Chrome/91.0',
            'expires_at' => now()->addHours(2),
        ]);

        // ASSERT: All tokens should be unique
        $this->assertNotEquals($session1->session_token, $session2->session_token);
        $this->assertNotEquals($session1->refresh_token, $session2->refresh_token);
    }
}
