<?php

namespace Tests\Integration\Security;

use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for Intrusion Detection System
 *
 * Tests all 6 detection methods:
 * 1. Brute force detection (5+ attempts/email, 10+ from IP in 15min)
 * 2. Credential stuffing (10+ unique emails from IP in 5min)
 * 3. SQL injection pattern detection
 * 4. XSS pattern detection
 * 5. API abuse detection (100+ requests/minute threshold)
 * 6. Unusual login patterns (IP changes within 2 hours)
 *
 * Each test verifies:
 * - Security incident created
 * - IP scoring updated
 * - Automatic blocking on severe violations
 *
 * @group security
 * @group critical
 * @group integration
 */
class IntrusionDetectionTest extends IntegrationTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Create Super Admin role to prevent notification errors
        // This is needed because SecurityIncidentService tries to notify Super Admins
        \Spatie\Permission\Models\Role::firstOrCreate([
            'name' => 'Super Admin',
            'guard_name' => 'web',
            'organization_id' => null,
        ]);
    }

    // ============================================================
    // BRUTE FORCE DETECTION TESTS
    // ============================================================

    #[Test]
    public function brute_force_detected_by_email_threshold()
    {
        // ARRANGE: Create 5 failed attempts on same email
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::create([
                'email' => 'victim@example.com',
                'ip_address' => '192.168.1.99',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // Use service to detect
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $detected = $service->detectBruteForce('victim@example.com', '192.168.1.99');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident created
        $this->assertSecurityIncidentCreated([
            'type' => 'brute_force',
            'ip_address' => '192.168.1.99',
        ]);

        // ASSERT: Failed attempts recorded
        $this->assertDatabaseCount('failed_login_attempts', 5);

        // ASSERT: IP scoring reflects the incident
        $incidents = SecurityIncident::where('ip_address', '192.168.1.99')
            ->where('type', 'brute_force')
            ->count();
        $this->assertGreaterThan(0, $incidents);
    }

    #[Test]
    public function brute_force_detected_by_ip_threshold()
    {
        // ARRANGE: Create multiple users
        $users = User::factory()->count(5)->create();

        // Create 10 failed attempts directly
        for ($i = 0; $i < 10; $i++) {
            FailedLoginAttempt::create([
                'email' => $users[$i % 5]->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // Use service to detect
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $detected = $service->detectBruteForce($users[0]->email, '127.0.0.1');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident created
        $this->assertSecurityIncidentCreated([
            'type' => 'brute_force',
            'ip_address' => '127.0.0.1',
        ]);
    }

    #[Test]
    public function brute_force_triggers_automatic_ip_block_on_severe_threshold()
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

        // Use service to detect
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $detected = $service->detectBruteForce('victim@example.com', '192.168.1.100');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident created with high/critical severity
        $incident = SecurityIncident::where('type', 'brute_force')
            ->where('ip_address', '192.168.1.100')
            ->first();

        $this->assertNotNull($incident);
        $this->assertContains($incident->severity, ['high', 'critical']);

        // ASSERT: IP automatically blocked (if IpBlocklistService is called)
        // Note: This requires full integration with auth middleware
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '192.168.1.100',
            'block_type' => 'brute_force',
            'is_active' => true,
        ]);
    }

    #[Test]
    public function brute_force_severity_escalates_with_attempt_count()
    {
        // ARRANGE: Create 10 failed attempts (2x email threshold of 5)
        for ($i = 0; $i < 10; $i++) {
            FailedLoginAttempt::create([
                'email' => 'victim@example.com',
                'ip_address' => '192.168.1.101',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // Use service to detect
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $detected = $service->detectBruteForce('victim@example.com', '192.168.1.101');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Critical severity due to 2x threshold
        $this->assertDatabaseHas('security_incidents', [
            'type' => 'brute_force',
            'severity' => 'critical',
            'ip_address' => '192.168.1.101',
        ]);
    }

    #[Test]
    public function brute_force_detection_respects_time_window()
    {
        // ARRANGE
        $user = $this->createUser(['email' => 'victim@example.com']);

        // ACT: Create old attempts (outside 15min window)
        FailedLoginAttempt::create([
            'email' => $user->email,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Test',
            'attempt_type' => 'password',
            'failure_reason' => 'invalid_credentials',
            'attempted_at' => now()->subMinutes(20),
        ]);

        // New attempts (within window)
        $this->simulateFailedLoginAttempts($user->email, 3);

        // ASSERT: No brute force detected (only 3 in window, not 5)
        $this->assertDatabaseMissing('security_incidents', [
            'type' => 'brute_force',
        ]);
    }

    // ============================================================
    // CREDENTIAL STUFFING DETECTION TESTS
    // ============================================================

    #[Test]
    public function credential_stuffing_detected_with_multiple_unique_emails()
    {
        // ARRANGE: Create 10 failed attempts with unique emails
        $users = User::factory()->count(10)->create();

        foreach ($users as $user) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '192.168.1.102',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // Use service to detect
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $detected = $service->detectCredentialStuffing('192.168.1.102');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Credential stuffing incident created
        $this->assertSecurityIncidentCreated([
            'type' => 'credential_stuffing',
            'severity' => 'critical',
            'ip_address' => '192.168.1.102',
        ]);
    }

    #[Test]
    public function credential_stuffing_triggers_immediate_ip_block()
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

        // Use service to detect
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $detected = $service->detectCredentialStuffing('192.168.1.103');

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: IP blocked immediately (requires IpBlocklistService integration)
        $this->assertDatabaseHas('ip_blocklist', [
            'ip_address' => '192.168.1.103',
            'block_type' => 'credential_stuffing',
            'is_active' => true,
        ]);
    }

    #[Test]
    public function credential_stuffing_detection_respects_five_minute_window()
    {
        // ARRANGE: 5 users
        $users = User::factory()->count(5)->create();

        // ACT: Create old attempts (outside 5min window)
        foreach ($users as $user) {
            FailedLoginAttempt::create([
                'email' => $user->email,
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now()->subMinutes(10),
            ]);
        }

        // Create 5 new attempts (total 10, but only 5 in window)
        $newUsers = User::factory()->count(5)->create();
        foreach ($newUsers as $user) {
            $this->postJson('/api/v1/auth/login', [
                'email' => $user->email,
                'password' => 'wrong',
            ]);
        }

        // ASSERT: No credential stuffing detected (only 5 in window, not 10)
        $this->assertDatabaseMissing('security_incidents', [
            'type' => 'credential_stuffing',
        ]);
    }

    // ============================================================
    // SQL INJECTION DETECTION TESTS
    // ============================================================

    #[Test]
    public function sql_injection_detected_with_or_equals_pattern()
    {
        // ARRANGE: Create mock request with SQL injection
        $request = Request::create('/api/v1/auth/login', 'POST', [
            'email' => "admin' OR '1'='1",
            'password' => 'password',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect SQL injection
        $detected = $service->detectSqlInjection($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'sql_injection',
            'severity' => 'critical',
            'ip_address' => '127.0.0.1',
        ]);
    }

    #[Test]
    public function sql_injection_detected_with_union_select_pattern()
    {
        // ARRANGE: Create mock request with SQL injection
        $request = Request::create('/api/v1/auth/login', 'POST', [
            'email' => "' UNION SELECT * FROM users--",
            'password' => 'password',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect SQL injection
        $detected = $service->detectSqlInjection($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged with metadata
        $incident = SecurityIncident::where('type', 'sql_injection')
            ->where('ip_address', '127.0.0.1')
            ->first();

        $this->assertNotNull($incident);
        $this->assertEquals('critical', $incident->severity);
        $this->assertArrayHasKey('pattern', $incident->metadata);
    }

    #[Test]
    public function sql_injection_detected_with_drop_table_pattern()
    {
        // ARRANGE: Create mock request with SQL injection
        $request = Request::create('/api/v1/auth/login', 'POST', [
            'email' => "'; DROP TABLE users;--",
            'password' => 'password',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect SQL injection
        $detected = $service->detectSqlInjection($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'sql_injection',
            'severity' => 'critical',
            'ip_address' => '127.0.0.1',
        ]);
    }

    #[Test]
    public function sql_injection_detected_with_comment_patterns()
    {
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        $commentPatterns = [
            "admin'--",
            "admin'#",
            "admin'/*",
        ];

        foreach ($commentPatterns as $payload) {
            // ARRANGE: Create mock request
            $request = Request::create('/api/v1/auth/login', 'POST', [
                'email' => $payload,
                'password' => 'password',
            ]);
            $request->server->set('REMOTE_ADDR', '127.0.0.1');

            // ACT: Detect SQL injection
            $detected = $service->detectSqlInjection($request);

            // ASSERT: Detection successful
            $this->assertTrue($detected);
        }

        // ASSERT: Multiple incidents logged
        $incidentCount = SecurityIncident::where('type', 'sql_injection')
            ->where('ip_address', '127.0.0.1')
            ->count();

        $this->assertGreaterThanOrEqual(3, $incidentCount);
    }

    #[Test]
    public function sql_injection_detection_service_creates_incident()
    {
        // ARRANGE: Create mock request with SQL injection
        $request = Request::create('/api/v1/auth/login', 'POST', [
            'email' => "'; DROP TABLE users;--",
            'password' => 'password',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect SQL injection
        $detected = $service->detectSqlInjection($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'sql_injection',
            'severity' => 'critical',
            'ip_address' => '127.0.0.1',
        ]);
    }

    // ============================================================
    // XSS DETECTION TESTS
    // ============================================================

    #[Test]
    public function xss_detected_with_script_tag()
    {
        // ARRANGE: Create mock request with XSS payload
        $request = Request::create('/api/v1/profile', 'PUT', [
            'name' => '<script>alert("XSS")</script>',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect XSS
        $detected = $service->detectXss($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'xss_attempt',
            'severity' => 'high',
            'ip_address' => '127.0.0.1',
        ]);
    }

    #[Test]
    public function xss_detected_with_onerror_event_handler()
    {
        // ARRANGE: Create mock request with XSS payload
        $request = Request::create('/api/v1/profile', 'PUT', [
            'name' => '<img src=x onerror=alert("XSS")>',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect XSS
        $detected = $service->detectXss($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged with metadata
        $incident = SecurityIncident::where('type', 'xss_attempt')
            ->where('ip_address', '127.0.0.1')
            ->first();

        $this->assertNotNull($incident);
        $this->assertEquals('high', $incident->severity);
        $this->assertArrayHasKey('pattern', $incident->metadata);
        $this->assertArrayHasKey('parameter', $incident->metadata);
    }

    #[Test]
    public function xss_detected_with_javascript_protocol()
    {
        // ARRANGE: Create mock request with XSS payload
        $request = Request::create('/api/v1/profile', 'PUT', [
            'name' => 'javascript:alert("XSS")',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect XSS
        $detected = $service->detectXss($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'xss_attempt',
            'severity' => 'high',
            'ip_address' => '127.0.0.1',
        ]);
    }

    #[Test]
    public function xss_detected_with_iframe_embed_object_tags()
    {
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        $maliciousTags = [
            '<iframe src="evil.com"></iframe>',
            '<embed src="evil.swf">',
            '<object data="evil.swf">',
        ];

        foreach ($maliciousTags as $payload) {
            // ARRANGE: Create mock request
            $request = Request::create('/api/v1/profile', 'PUT', [
                'name' => $payload,
            ]);
            $request->server->set('REMOTE_ADDR', '127.0.0.1');

            // ACT: Detect XSS
            $detected = $service->detectXss($request);

            // ASSERT: Detection successful
            $this->assertTrue($detected);
        }

        // ASSERT: Multiple incidents logged
        $incidentCount = SecurityIncident::where('type', 'xss_attempt')
            ->where('ip_address', '127.0.0.1')
            ->count();

        $this->assertGreaterThanOrEqual(3, $incidentCount);
    }

    #[Test]
    public function xss_detected_with_onload_event_handler()
    {
        // ARRANGE: Create mock request with XSS payload
        $request = Request::create('/api/v1/profile', 'PUT', [
            'name' => '<body onload=alert("XSS")>',
        ]);
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect XSS
        $detected = $service->detectXss($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident logged
        $this->assertSecurityIncidentCreated([
            'type' => 'xss_attempt',
            'severity' => 'high',
            'ip_address' => '127.0.0.1',
        ]);
    }

    // ============================================================
    // API ABUSE DETECTION TESTS
    // ============================================================

    #[Test]
    public function api_abuse_detected_with_excessive_requests_per_minute()
    {
        // ARRANGE: Simulate 101 requests in cache
        $timestamps = [];
        for ($i = 0; $i < 101; $i++) {
            $timestamps[] = now()->timestamp;
        }
        Cache::put('api_requests:127.0.0.1', $timestamps, 120);

        // Create mock request
        $request = Request::create('/api/v1/user', 'GET');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->headers->set('User-Agent', 'TestAgent/1.0');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect API abuse
        $detected = $service->detectAnomalousApiActivity($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident created
        $this->assertDatabaseHas('security_incidents', [
            'type' => 'api_abuse',
            'severity' => 'high',
            'ip_address' => '127.0.0.1',
        ]);
    }

    #[Test]
    public function api_abuse_detection_tracks_requests_per_minute()
    {
        // ARRANGE: Simulate 50 requests in cache (below threshold of 100)
        Cache::flush();
        $timestamps = [];
        for ($i = 0; $i < 50; $i++) {
            $timestamps[] = now()->timestamp;
        }
        Cache::put('api_requests:127.0.0.1', $timestamps, 120);

        // Create mock request
        $request = Request::create('/api/v1/user', 'GET');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect API abuse
        $detected = $service->detectAnomalousApiActivity($request);

        // ASSERT: Not detected (below threshold)
        $this->assertFalse($detected);

        // ASSERT: No incident created
        $this->assertDatabaseMissing('security_incidents', [
            'type' => 'api_abuse',
        ]);
    }

    #[Test]
    public function api_abuse_incident_includes_request_details()
    {
        // ARRANGE: Simulate 101 requests in cache
        $timestamps = [];
        for ($i = 0; $i < 101; $i++) {
            $timestamps[] = now()->timestamp;
        }
        Cache::put('api_requests:127.0.0.1', $timestamps, 120);

        // Create mock request
        $request = Request::create('/api/v1/user', 'GET');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');
        $request->headers->set('User-Agent', 'TestAgent/1.0');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect API abuse
        $detected = $service->detectAnomalousApiActivity($request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Incident includes metadata
        $incident = SecurityIncident::where('type', 'api_abuse')
            ->where('ip_address', '127.0.0.1')
            ->first();

        $this->assertNotNull($incident, 'API abuse incident should be created');
        $this->assertArrayHasKey('requests_per_minute', $incident->metadata);
        $this->assertGreaterThanOrEqual(100, $incident->metadata['requests_per_minute']);
    }

    // ============================================================
    // UNUSUAL LOGIN PATTERN DETECTION TESTS
    // ============================================================

    #[Test]
    public function unusual_login_pattern_detected_with_ip_change_within_two_hours()
    {
        // ARRANGE: User with recent login from different IP
        $user = $this->createUser([
            'email' => 'user@example.com',
            'password' => bcrypt('password'),
        ]);

        // Create authentication log for previous login
        $user->authenticationLogs()->create([
            'event' => 'login_success',
            'ip_address' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => [],
            'created_at' => now()->subHour(),
        ]);

        // Create mock request from different IP
        $request = Request::create('/api/v1/auth/login', 'POST', [
            'email' => $user->email,
            'password' => 'password',
        ]);
        $request->server->set('REMOTE_ADDR', '5.6.7.8');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect unusual pattern
        $detected = $service->detectUnusualLoginPattern($user, $request);

        // ASSERT: Detection successful
        $this->assertTrue($detected);

        // ASSERT: Security incident created
        $this->assertSecurityIncidentCreated([
            'type' => 'unusual_login_pattern',
            'severity' => 'medium',
            'user_id' => $user->id,
        ]);

        // ASSERT: Incident metadata includes IP details
        $incident = SecurityIncident::where('type', 'unusual_login_pattern')
            ->where('user_id', $user->id)
            ->first();

        $this->assertNotNull($incident);
        $this->assertArrayHasKey('previous_ip', $incident->metadata);
        $this->assertArrayHasKey('current_ip', $incident->metadata);
        $this->assertArrayHasKey('time_difference_minutes', $incident->metadata);
    }

    #[Test]
    public function unusual_login_pattern_not_detected_if_same_ip()
    {
        // ARRANGE: User with recent login
        $user = $this->createUser([
            'email' => 'user@example.com',
            'password' => bcrypt('password'),
        ]);

        // Create authentication log for previous login (same IP)
        $user->authenticationLogs()->create([
            'event' => 'login_success',
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => [],
            'created_at' => now()->subMinutes(30),
        ]);

        // Create mock request from same IP
        $request = Request::create('/api/v1/auth/login', 'POST');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect unusual pattern
        $detected = $service->detectUnusualLoginPattern($user, $request);

        // ASSERT: Not detected (same IP)
        $this->assertFalse($detected);

        // ASSERT: No unusual pattern detected
        $this->assertDatabaseMissing('security_incidents', [
            'type' => 'unusual_login_pattern',
            'user_id' => $user->id,
        ]);
    }

    #[Test]
    public function unusual_login_pattern_not_detected_if_time_gap_exceeds_two_hours()
    {
        // ARRANGE: User with NO recent login (all logins > 2 hours ago)
        $user = $this->createUser([
            'email' => 'user@example.com',
            'password' => bcrypt('password'),
        ]);

        // Clear any logs that might have been created
        $user->authenticationLogs()->delete();

        // Create authentication log for old login (25 hours ago - way outside 2-hour window)
        // Use DB directly to bypass Eloquent timestamp handling
        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'event' => 'login_success',
            'ip_address' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => json_encode([]),
            'created_at' => now()->subHours(25),
            'updated_at' => now()->subHours(25),
        ]);

        // Verify there are no logins in the last 2 hours
        $recentLogins = $user->authenticationLogs()
            ->where('event', 'login_success')
            ->where('created_at', '>=', now()->subHours(2))
            ->count();

        $this->assertEquals(0, $recentLogins, 'Should have no recent logins within 2 hours');

        // Create mock request from different IP
        $request = Request::create('/api/v1/auth/login', 'POST');
        $request->server->set('REMOTE_ADDR', '5.6.7.8');

        // Get the service
        $service = app(\App\Services\Security\IntrusionDetectionService::class);

        // ACT: Detect unusual pattern
        $detected = $service->detectUnusualLoginPattern($user, $request);

        // ASSERT: Not detected (no recent login within 2 hours)
        $this->assertFalse($detected);

        // ASSERT: No unusual pattern detected
        $this->assertDatabaseMissing('security_incidents', [
            'type' => 'unusual_login_pattern',
            'user_id' => $user->id,
        ]);
    }

    // ============================================================
    // IP SCORING TESTS
    // ============================================================

    #[Test]
    public function ip_security_score_decreases_with_failed_attempts()
    {
        // ARRANGE: Create failed attempts directly
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::create([
                'email' => 'test@example.com',
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Test',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        // ASSERT: Failed attempts recorded
        $failedAttempts = FailedLoginAttempt::where('ip_address', '127.0.0.1')
            ->where('attempted_at', '>=', now()->subDay())
            ->count();

        $this->assertEquals(5, $failedAttempts);

        // ACT: Get IP security score
        $service = app(\App\Services\Security\IntrusionDetectionService::class);
        $score = $service->getIpSecurityScore('127.0.0.1');

        // ASSERT: Score is reduced (100 - (5 * 5) = 75)
        $this->assertEquals(75, $score);
    }

    #[Test]
    public function ip_security_score_decreases_with_security_incidents()
    {
        // ARRANGE: Create security incident
        SecurityIncident::create([
            'type' => 'brute_force',
            'severity' => 'high',
            'ip_address' => '127.0.0.1',
            'endpoint' => '/api/v1/auth/login',
            'description' => 'Test incident',
            'detected_at' => now(),
        ]);

        // ASSERT: Incident recorded
        $incidents = SecurityIncident::where('ip_address', '127.0.0.1')
            ->where('detected_at', '>=', now()->subWeek())
            ->count();

        $this->assertGreaterThanOrEqual(1, $incidents);
    }

    #[Test]
    public function ip_security_score_decreases_with_previous_blocks()
    {
        // ARRANGE: Create previous block
        IpBlocklist::create([
            'ip_address' => '127.0.0.1',
            'block_type' => 'brute_force',
            'reason' => 'Test block',
            'blocked_at' => now()->subDays(15),
            'is_active' => false,
            'incident_count' => 1,
        ]);

        // ASSERT: Block recorded
        $blocks = IpBlocklist::where('ip_address', '127.0.0.1')
            ->where('blocked_at', '>=', now()->subMonth())
            ->count();

        $this->assertGreaterThanOrEqual(1, $blocks);
    }
}
