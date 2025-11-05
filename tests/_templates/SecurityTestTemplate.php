<?php

namespace Tests\Integration\Security;

use App\Models\User;
use App\Notifications\AccountLockedNotification;
use Tests\Integration\IntegrationTestCase;

/**
 * Template for Security Integration Tests
 *
 * Security tests verify protection mechanisms including intrusion detection,
 * progressive lockout, organization boundaries, and security headers.
 *
 * Key security testing principles:
 * 1. Test attack scenarios (not just happy paths)
 * 2. Verify detection and response mechanisms
 * 3. Verify side effects (incident logs, notifications, blocking)
 * 4. Test boundary conditions (rate limits, lockout thresholds)
 * 5. Verify security headers and protections
 *
 * @group security
 * @group critical
 * @group integration
 */
class ExampleSecurityTest extends IntegrationTestCase
{
    /**
     * Test intrusion detection and response
     *
     * @test
     */
    public function attack_scenario_triggers_detection_and_response()
    {
        // ============================================================
        // ARRANGE: Set up vulnerable scenario
        // ============================================================
        $user = $this->createUser([
            'email' => 'target@example.com',
        ]);

        // ============================================================
        // ACT: Simulate attack (e.g., brute force)
        // ============================================================
        $this->simulateFailedLoginAttempts($user->email, 3);

        // ============================================================
        // ASSERT 1: Verify detection
        // ============================================================
        $this->assertSecurityIncidentCreated([
            'user_id' => $user->id,
            'type' => 'brute_force',
            'severity' => 'medium',
        ]);

        // ============================================================
        // ASSERT 2: Verify response (account locked)
        // ============================================================
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'locked_until' => now()->addMinutes(5)->toDateTimeString(),
        ]);

        // ============================================================
        // ASSERT 3: Verify notification sent
        // ============================================================
        $this->assertNotificationSentTo($user, AccountLockedNotification::class);

        // ============================================================
        // ASSERT 4: Verify subsequent attempts blocked
        // ============================================================
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'correct-password',
        ]);

        $response->assertStatus(429); // Too Many Requests
        $response->assertJson([
            'message' => 'Account temporarily locked',
        ]);
    }

    /**
     * Test progressive lockout escalation
     *
     * @test
     */
    public function progressive_lockout_escalates_correctly()
    {
        // ARRANGE
        $user = $this->createUser();

        // ACT & ASSERT: 3 attempts → 5 min lockout
        $this->simulateFailedLoginAttempts($user->email, 3);
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'failed_login_attempts' => 3,
        ]);

        // Unlock and test next level
        $user->update(['locked_until' => null, 'failed_login_attempts' => 5]);

        // ACT & ASSERT: 5 attempts → 15 min lockout
        $this->simulateFailedLoginAttempts($user->email, 2);
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'failed_login_attempts' => 7,
        ]);

        // Continue testing escalation levels...
    }

    /**
     * Test IP-based attack detection
     *
     * @test
     */
    public function ip_based_attack_detected_and_blocked()
    {
        // ARRANGE: Multiple users from same IP
        $users = User::factory()->count(5)->create();

        // ACT: Simulate credential stuffing (many users, same IP)
        foreach ($users as $user) {
            $this->postJson('/api/v1/auth/login', [
                'email' => $user->email,
                'password' => 'wrong-password',
            ]);
        }

        // ASSERT: Security incident created
        $this->assertSecurityIncidentCreated([
            'type' => 'credential_stuffing',
            'severity' => 'high',
        ]);

        // ASSERT: IP blocked
        $this->assertDatabaseHas('ip_blocks', [
            'ip_address' => '127.0.0.1',
            'blocked_until' => now()->addHours(24)->toDateTimeString(),
        ]);

        // ASSERT: Subsequent requests from IP blocked
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $users[0]->email,
            'password' => 'correct-password',
        ]);

        $response->assertStatus(403);
    }

    /**
     * Test SQL injection detection
     *
     * @test
     */
    public function sql_injection_attempt_detected_and_blocked()
    {
        // ARRANGE
        $user = $this->createUser();

        // ACT: Attempt SQL injection in various fields
        $sqlInjectionPayloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users;--",
        ];

        foreach ($sqlInjectionPayloads as $payload) {
            $response = $this->postJson('/api/v1/auth/login', [
                'email' => $payload,
                'password' => 'password',
            ]);

            // ASSERT: Request blocked
            $response->assertStatus(400);
        }

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'sql_injection',
            'severity' => 'critical',
        ]);
    }

    /**
     * Test XSS attack detection
     *
     * @test
     */
    public function xss_attempt_detected_and_blocked()
    {
        // ARRANGE
        $user = $this->createUser();

        // ACT: Attempt XSS in profile update
        $xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
        ];

        foreach ($xssPayloads as $payload) {
            $response = $this->actingAs($user)->patchJson('/api/v1/profile', [
                'name' => $payload,
            ]);

            // ASSERT: Request sanitized or blocked
            $response->assertStatus(422);
        }

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'xss_attempt',
            'severity' => 'high',
        ]);
    }

    /**
     * Test organization boundary enforcement
     *
     * @test
     */
    public function user_cannot_access_another_organization_data()
    {
        // ARRANGE: Two organizations
        $org1 = $this->createOrganization(['name' => 'Org 1']);
        $org2 = $this->createOrganization(['name' => 'Org 2']);

        $userOrg1 = $this->createUser(['organization_id' => $org1->id]);
        $userOrg2 = $this->createUser(['organization_id' => $org2->id]);

        // ACT: User from Org1 tries to access Org2 user
        $response = $this->actingAs($userOrg1)
            ->getJson("/api/v1/users/{$userOrg2->id}");

        // ASSERT: Returns 404 (not 403!) to prevent information leakage
        $response->assertNotFound();

        // ASSERT: Boundary violation logged
        $this->assertAuthenticationLogged([
            'user_id' => $userOrg1->id,
            'event_type' => 'boundary_violation',
        ]);

        // Test other resources
        $this->assertOrganizationBoundaryEnforced(
            $userOrg1,
            "/api/v1/users/{$userOrg2->id}",
            'GET'
        );
    }

    /**
     * Test security headers are present
     *
     * @test
     */
    public function security_headers_present_on_responses()
    {
        // ARRANGE
        $user = $this->createUser();

        // ACT: Make request
        $response = $this->actingAs($user)->getJson('/api/v1/user');

        // ASSERT: Security headers present
        $this->assertHasSecurityHeaders();

        // Verify specific header values
        $this->assertEquals(
            'DENY',
            $response->headers->get('X-Frame-Options')
        );

        $this->assertEquals(
            'nosniff',
            $response->headers->get('X-Content-Type-Options')
        );

        $this->assertStringContainsString(
            'max-age=',
            $response->headers->get('Strict-Transport-Security')
        );
    }

    /**
     * Test CSP headers on admin panel
     *
     * @test
     */
    public function csp_headers_present_on_admin_panel()
    {
        // ARRANGE
        $admin = $this->createSuperAdmin();

        // ACT: Access admin panel
        $response = $this->actingAs($admin)->get('/admin');

        // ASSERT: CSP header present with nonce
        $cspHeader = $response->headers->get('Content-Security-Policy');
        $this->assertNotNull($cspHeader);
        $this->assertStringContainsString('script-src', $cspHeader);
        $this->assertStringContainsString('nonce-', $cspHeader);
    }

    /**
     * Test rate limiting enforcement
     *
     * @test
     */
    public function rate_limiting_blocks_excessive_requests()
    {
        // ARRANGE
        $user = $this->createUser();

        // ACT: Make requests up to limit
        $limit = 10; // Assume rate limit is 10/minute

        for ($i = 0; $i < $limit; $i++) {
            $response = $this->actingAs($user)
                ->postJson('/api/v1/auth/login', [
                    'email' => $user->email,
                    'password' => 'wrong',
                ]);

            // Should work within limit
            $this->assertContains($response->status(), [401, 422]);
        }

        // ACT: Exceed limit
        $response = $this->actingAs($user)
            ->postJson('/api/v1/auth/login', [
                'email' => $user->email,
                'password' => 'wrong',
            ]);

        // ASSERT: Rate limit exceeded
        $response->assertStatus(429);
        $response->assertJsonStructure([
            'message',
            'retry_after',
        ]);
    }

    /**
     * Test unusual login pattern detection
     *
     * @test
     */
    public function unusual_login_pattern_triggers_alert()
    {
        // ARRANGE
        $user = $this->createUser();

        // ACT: Simulate login from one IP
        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ], ['REMOTE_ADDR' => '1.2.3.4']);

        // Wait briefly
        sleep(1);

        // ACT: Simulate login from different IP shortly after
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ], ['REMOTE_ADDR' => '5.6.7.8']);

        // ASSERT: Unusual pattern detected
        $this->assertSecurityIncidentCreated([
            'user_id' => $user->id,
            'type' => 'unusual_login_pattern',
            'severity' => 'medium',
        ]);

        // ASSERT: User notified
        $this->assertNotificationSentTo($user, \App\Notifications\UnusualLoginNotification::class);
    }
}
