<?php

namespace Tests\Integration\Security;

use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\SecurityIncident;
use App\Models\User;
use App\Services\Security\IntrusionDetectionService;
use App\Services\Security\IpBlocklistService;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for IP Blocking System
 *
 * Tests IP blocking features:
 * 1. Automatic IP blocking on severe violations
 * 2. Manual IP blocking (temporary and permanent)
 * 3. IP security score calculation (0-100)
 * 4. Blocked IP cannot access any endpoint
 * 5. IP unblocking process
 *
 * Each test verifies:
 * - IpBlocklist records created/updated
 * - Blocked IPs rejected at API endpoints
 * - Security score calculation accuracy
 * - Block expiration handling
 */
#[\PHPUnit\Framework\Attributes\Group('security')]
#[\PHPUnit\Framework\Attributes\Group('critical')]
#[\PHPUnit\Framework\Attributes\Group('integration')]
class IpBlockingTest extends IntegrationTestCase
{
    protected IpBlocklistService $blocklistService;

    protected IntrusionDetectionService $intrusionService;

    protected function setUp(): void
    {
        parent::setUp();

        // Initialize services
        $this->blocklistService = app(IpBlocklistService::class);
        $this->intrusionService = app(IntrusionDetectionService::class);

        // Create Super Admin role to prevent notification errors
        \Spatie\Permission\Models\Role::firstOrCreate([
            'name' => 'Super Admin',
            'guard_name' => 'web',
            'organization_id' => null,
        ]);
    }

    // ============================================================
    // AUTOMATIC IP BLOCKING TESTS
    // ============================================================

    #[Test]
    public function automatic_ip_blocking_triggers_on_severe_brute_force()
    {
        // ARRANGE: Create 20 failed attempts (2x threshold of 10)
        for ($i = 0; $i < 20; $i++) {
            FailedLoginAttempt::create([
                'email' => 'victim@example.com',
                'ip_address' => '192.168.1.100',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Detect brute force
        $detected = $this->intrusionService->detectBruteForce('victim@example.com', '192.168.1.100');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: IP automatically blocked
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '192.168.1.100',
            'block_type' => 'brute_force',
            'is_active' => true,
        ]);

        // ASSERT: IP is blocked via service
        $this->assertTrue($this->blocklistService->isIpBlocked('192.168.1.100'));
    }

    #[Test]
    public function automatic_ip_blocking_triggers_on_credential_stuffing()
    {
        // ARRANGE: Create 10 failed attempts with unique emails
        $users = User::factory()->count(10)->create();

        foreach ($users as $user) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '192.168.1.103',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Detect credential stuffing
        $detected = $this->intrusionService->detectCredentialStuffing('192.168.1.103');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: IP blocked immediately
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '192.168.1.103',
            'block_type' => 'credential_stuffing',
            'is_active' => true,
        ]);

        // ASSERT: IP is blocked via service
        $this->assertTrue($this->blocklistService->isIpBlocked('192.168.1.103'));
    }

    #[Test]
    public function automatic_ip_blocking_creates_security_incident()
    {
        // ARRANGE: Create severe violation (20 failed attempts)
        for ($i = 0; $i < 20; $i++) {
            FailedLoginAttempt::create([
                'email' => 'victim@example.com',
                'ip_address' => '192.168.1.101',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Detect brute force
        $detected = $this->intrusionService->detectBruteForce('victim@example.com', '192.168.1.101');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident created
        $this->assertSecurityIncidentCreated([
            'type' => 'brute_force',
            'severity' => 'critical',
            'ip_address' => '192.168.1.101',
        ]);

        // ASSERT: IP blocked
        $this->assertTrue($this->blocklistService->isIpBlocked('192.168.1.101'));
    }

    // ============================================================
    // MANUAL IP BLOCKING TESTS
    // ============================================================

    #[Test]
    public function manual_temporary_ip_block_with_default_duration()
    {
        // ARRANGE: Admin user
        $admin = $this->createSuperAdmin();

        // ACT: Block IP temporarily (default 24 hours)
        $block = $this->blocklistService->blockIp(
            '10.0.0.1',
            'temporary',
            'Manual block by admin',
            null,
            $admin
        );

        // ASSERT: Block created
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '10.0.0.1',
            'block_type' => 'temporary',
            'reason' => 'Manual block by admin',
            'blocked_by' => $admin->id,
            'is_active' => true,
        ]);

        // ASSERT: Expires in 24 hours (allow 1 second variance)
        $expectedExpiry = now()->addHours(24);
        $this->assertTrue(
            abs($block->expires_at->timestamp - $expectedExpiry->timestamp) <= 1,
            'Default temporary block should expire in 24 hours'
        );

        // ASSERT: IP is blocked
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.0.1'));
    }

    #[Test]
    public function manual_temporary_ip_block_with_custom_duration()
    {
        // ARRANGE: Admin user
        $admin = $this->createSuperAdmin();

        // ACT: Block IP temporarily for 2 hours
        $block = $this->blocklistService->blockIp(
            '10.0.0.2',
            'temporary',
            'Custom duration block',
            2,
            $admin
        );

        // ASSERT: Block created with custom duration
        $expectedExpiry = now()->addHours(2);
        $this->assertTrue(
            abs($block->expires_at->timestamp - $expectedExpiry->timestamp) <= 1,
            'Custom temporary block should expire in 2 hours'
        );

        // ASSERT: IP is blocked
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.0.2'));
    }

    #[Test]
    public function manual_permanent_ip_block()
    {
        // ARRANGE: Admin user
        $admin = $this->createSuperAdmin();

        // ACT: Block IP permanently
        $block = $this->blocklistService->blockIp(
            '10.0.0.3',
            'permanent',
            'Permanent ban for repeated violations',
            null,
            $admin
        );

        // ASSERT: Block created without expiry
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '10.0.0.3',
            'block_type' => 'permanent',
            'reason' => 'Permanent ban for repeated violations',
            'blocked_by' => $admin->id,
            'is_active' => true,
        ]);

        // ASSERT: No expiry date
        $this->assertNull($block->expires_at);

        // ASSERT: IP is blocked
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.0.3'));
    }

    #[Test]
    public function manual_ip_block_updates_existing_block()
    {
        // ARRANGE: Existing block
        $existingBlock = IpBlocklist::create([
            'ip_address' => '10.0.0.4',
            'block_type' => 'temporary',
            'reason' => 'Initial block',
            'blocked_at' => now(),
            'expires_at' => now()->addHours(1),
            'incident_count' => 1,
            'is_active' => true,
        ]);

        // ACT: Block again (should update existing)
        $updatedBlock = $this->blocklistService->blockIp(
            '10.0.0.4',
            'permanent',
            'Upgraded to permanent'
        );

        // ASSERT: Same block updated
        $this->assertEquals($existingBlock->id, $updatedBlock->id);

        // ASSERT: Block details updated
        $this->assertEquals('permanent', $updatedBlock->block_type);
        $this->assertEquals('Upgraded to permanent', $updatedBlock->reason);
        $this->assertEquals(2, $updatedBlock->incident_count);
    }

    // ============================================================
    // IP SECURITY SCORE CALCULATION TESTS
    // ============================================================

    #[Test]
    public function ip_security_score_starts_at_100_for_clean_ip()
    {
        // ACT: Get score for clean IP
        $score = $this->intrusionService->getIpSecurityScore('192.168.1.200');

        // ASSERT: Perfect score
        $this->assertEquals(100, $score);
    }

    #[Test]
    public function ip_security_score_decreases_with_failed_attempts()
    {
        // ARRANGE: Create 5 failed attempts
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::create([
                'email' => 'test@example.com',
                'ip_address' => '192.168.1.201',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ACT: Get IP security score
        $score = $this->intrusionService->getIpSecurityScore('192.168.1.201');

        // ASSERT: Score reduced by 5 points per attempt (100 - (5 * 5) = 75)
        $this->assertEquals(75, $score);
    }

    #[Test]
    public function ip_security_score_decreases_with_security_incidents()
    {
        // ARRANGE: Create security incident
        SecurityIncident::create([
            'type' => 'brute_force',
            'severity' => 'high',
            'ip_address' => '192.168.1.202',
            'endpoint' => '/api/v1/auth/login',
            'description' => 'Test incident',
            'detected_at' => now(),
        ]);

        // ACT: Get IP security score
        $score = $this->intrusionService->getIpSecurityScore('192.168.1.202');

        // ASSERT: Score reduced by 10 points per incident (100 - 10 = 90)
        $this->assertEquals(90, $score);
    }

    #[Test]
    public function ip_security_score_decreases_with_previous_blocks()
    {
        // ARRANGE: Create previous block
        IpBlocklist::create([
            'ip_address' => '192.168.1.203',
            'block_type' => 'brute_force',
            'reason' => 'Test block',
            'blocked_at' => now()->subDays(15),
            'is_active' => false,
            'incident_count' => 1,
        ]);

        // ACT: Get IP security score
        $score = $this->intrusionService->getIpSecurityScore('192.168.1.203');

        // ASSERT: Score reduced by 20 points per block (100 - 20 = 80)
        $this->assertEquals(80, $score);
    }

    #[Test]
    public function ip_security_score_combines_all_factors()
    {
        // ARRANGE: Create failed attempts, incidents, and blocks
        $ipAddress = '192.168.1.204';

        // 3 failed attempts (-15 points)
        for ($i = 0; $i < 3; $i++) {
            FailedLoginAttempt::create([
                'email' => 'test@example.com',
                'ip_address' => $ipAddress,
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // 2 security incidents (-20 points)
        for ($i = 0; $i < 2; $i++) {
            SecurityIncident::create([
                'type' => 'brute_force',
                'severity' => 'high',
                'ip_address' => $ipAddress,
                'endpoint' => '/api/v1/auth/login',
                'description' => 'Test incident',
                'detected_at' => now()->subDays($i),
            ]);
        }

        // 1 previous block (-20 points)
        IpBlocklist::create([
            'ip_address' => $ipAddress,
            'block_type' => 'temporary',
            'reason' => 'Test block',
            'blocked_at' => now()->subDays(15),
            'is_active' => false,
            'incident_count' => 1,
        ]);

        // ACT: Get IP security score
        $score = $this->intrusionService->getIpSecurityScore($ipAddress);

        // ASSERT: Score reduced by all factors (100 - 15 - 20 - 20 = 45)
        $this->assertEquals(45, $score);
    }

    #[Test]
    public function ip_security_score_never_goes_below_zero()
    {
        // ARRANGE: Create excessive violations
        $ipAddress = '192.168.1.205';

        // 20 failed attempts (-50 points, capped at 50)
        for ($i = 0; $i < 20; $i++) {
            FailedLoginAttempt::create([
                'email' => 'test@example.com',
                'ip_address' => $ipAddress,
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // 10 security incidents (-40 points, capped at 40)
        for ($i = 0; $i < 10; $i++) {
            SecurityIncident::create([
                'type' => 'brute_force',
                'severity' => 'high',
                'ip_address' => $ipAddress,
                'endpoint' => '/api/v1/auth/login',
                'description' => 'Test incident',
                'detected_at' => now()->subDays($i % 6), // Within 1 week
            ]);
        }

        // 1 previous block (-20 points, capped at 30 max but only 1 block)
        // Note: IP address has unique constraint, so only one block per IP
        IpBlocklist::create([
            'ip_address' => $ipAddress,
            'block_type' => 'temporary',
            'reason' => 'Previous violation',
            'blocked_at' => now()->subDays(10),
            'expires_at' => now()->subDays(9),
            'is_active' => false,
            'incident_count' => 1,
        ]);

        // ACT: Get IP security score
        $score = $this->intrusionService->getIpSecurityScore($ipAddress);

        // ASSERT: Score is 0 (100 - 50 - 40 - 20 = -10, capped at 0)
        $this->assertEquals(0, $score);
    }

    // ============================================================
    // BLOCKED IP VERIFICATION TESTS
    // ============================================================
    // Note: HTTP endpoint blocking tests would require IP blocking middleware
    // which is not yet implemented. These tests verify the service layer only.

    #[Test]
    public function blocked_ip_is_identified_by_service()
    {
        // ARRANGE: Block IP
        $this->blocklistService->blockIp('10.0.0.50', 'temporary', 'Test block');

        // ACT & ASSERT: Service identifies blocked IP
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.0.50'));

        // ACT & ASSERT: Service identifies unblocked IP
        $this->assertFalse($this->blocklistService->isIpBlocked('10.0.0.99'));
    }

    #[Test]
    public function blocked_ip_list_is_cached()
    {
        // ARRANGE: Block multiple IPs
        $this->blocklistService->blockIp('10.0.1.1', 'temporary', 'Test 1');
        $this->blocklistService->blockIp('10.0.1.2', 'temporary', 'Test 2');
        $this->blocklistService->blockIp('10.0.1.3', 'permanent', 'Test 3');

        // ACT: Get blocked IPs (should be cached)
        $blockedIps = $this->blocklistService->getBlockedIps();

        // ASSERT: All blocked IPs returned
        $this->assertCount(3, $blockedIps);
        $this->assertTrue($blockedIps->contains('10.0.1.1'));
        $this->assertTrue($blockedIps->contains('10.0.1.2'));
        $this->assertTrue($blockedIps->contains('10.0.1.3'));
    }

    #[Test]
    public function expired_blocks_not_included_in_blocked_ips()
    {
        // ARRANGE: Create expired block
        IpBlocklist::create([
            'ip_address' => '10.0.1.10',
            'block_type' => 'temporary',
            'reason' => 'Expired block',
            'blocked_at' => now()->subHours(25),
            'expires_at' => now()->subHour(),
            'incident_count' => 1,
            'is_active' => true, // Still marked active but expired
        ]);

        // ACT: Get blocked IPs (should exclude expired)
        $blockedIps = $this->blocklistService->getBlockedIps();

        // ASSERT: Expired block not in list
        $this->assertFalse($blockedIps->contains('10.0.1.10'));
    }

    #[Test]
    public function unblocked_ip_removed_from_blocked_list()
    {
        // ARRANGE: Block then unblock IP
        $this->blocklistService->blockIp('10.0.1.20', 'temporary', 'Test block');
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.1.20'));

        // ACT: Unblock IP
        $this->blocklistService->unblockIp('10.0.1.20');

        // ASSERT: IP no longer in blocked list
        $this->assertFalse($this->blocklistService->isIpBlocked('10.0.1.20'));

        // ASSERT: IP not in cached blocked list
        $blockedIps = $this->blocklistService->getBlockedIps();
        $this->assertFalse($blockedIps->contains('10.0.1.20'));
    }

    // ============================================================
    // IP UNBLOCKING TESTS
    // ============================================================

    #[Test]
    public function manual_ip_unblock_deactivates_block()
    {
        // ARRANGE: Blocked IP
        IpBlocklist::create([
            'ip_address' => '10.0.0.10',
            'block_type' => 'temporary',
            'reason' => 'Test block',
            'blocked_at' => now(),
            'expires_at' => now()->addHours(24),
            'incident_count' => 1,
            'is_active' => true,
        ]);

        // ASSERT: IP is blocked
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.0.10'));

        // ACT: Unblock IP
        $result = $this->blocklistService->unblockIp('10.0.0.10');

        // ASSERT: Unblock successful
        $this->assertTrue($result);

        // ASSERT: Block deactivated
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '10.0.0.10',
            'is_active' => false,
        ]);

        // ASSERT: IP no longer blocked
        $this->assertFalse($this->blocklistService->isIpBlocked('10.0.0.10'));
    }

    #[Test]
    public function automatic_ip_unblock_when_temporary_block_expires()
    {
        // ARRANGE: Expired block
        IpBlocklist::create([
            'ip_address' => '10.0.0.11',
            'block_type' => 'temporary',
            'reason' => 'Test block',
            'blocked_at' => now()->subHours(25),
            'expires_at' => now()->subHour(), // Expired 1 hour ago
            'incident_count' => 1,
            'is_active' => true,
        ]);

        // ACT: Run expiration process
        $expiredCount = $this->blocklistService->expireBlocks();

        // ASSERT: Block expired
        $this->assertEquals(1, $expiredCount);

        // ASSERT: Block deactivated
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '10.0.0.11',
            'is_active' => false,
        ]);

        // ASSERT: IP no longer blocked
        $this->assertFalse($this->blocklistService->isIpBlocked('10.0.0.11'));
    }

    #[Test]
    public function permanent_ip_blocks_never_auto_expire()
    {
        // ARRANGE: Permanent block
        IpBlocklist::create([
            'ip_address' => '10.0.0.12',
            'block_type' => 'permanent',
            'reason' => 'Permanent ban',
            'blocked_at' => now()->subMonths(6),
            'expires_at' => null,
            'incident_count' => 5,
            'is_active' => true,
        ]);

        // ACT: Run expiration process
        $expiredCount = $this->blocklistService->expireBlocks();

        // ASSERT: No blocks expired
        $this->assertEquals(0, $expiredCount);

        // ASSERT: Block still active
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '10.0.0.12',
            'is_active' => true,
        ]);

        // ASSERT: IP still blocked
        $this->assertTrue($this->blocklistService->isIpBlocked('10.0.0.12'));
    }

    #[Test]
    public function unblocking_nonexistent_ip_returns_false()
    {
        // ACT: Try to unblock IP that was never blocked
        $result = $this->blocklistService->unblockIp('10.0.0.99');

        // ASSERT: Returns false
        $this->assertFalse($result);
    }

    #[Test]
    public function get_block_details_returns_active_block_information()
    {
        // ARRANGE: Active block
        $block = IpBlocklist::create([
            'ip_address' => '10.0.0.13',
            'block_type' => 'temporary',
            'reason' => 'Test block with details',
            'blocked_at' => now(),
            'expires_at' => now()->addHours(12),
            'incident_count' => 3,
            'is_active' => true,
        ]);

        // ACT: Get block details
        $details = $this->blocklistService->getBlockDetails('10.0.0.13');

        // ASSERT: Details returned
        $this->assertNotNull($details);
        $this->assertEquals($block->id, $details->id);
        $this->assertEquals('temporary', $details->block_type);
        $this->assertEquals('Test block with details', $details->reason);
        $this->assertEquals(3, $details->incident_count);
    }

    #[Test]
    public function get_block_details_returns_null_for_unblocked_ip()
    {
        // ACT: Get details for unblocked IP
        $details = $this->blocklistService->getBlockDetails('10.0.0.99');

        // ASSERT: Returns null
        $this->assertNull($details);
    }
}
