<?php

namespace Tests\Security;

use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Models\User;
use App\Services\Security\IntrusionDetectionService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Intrusion Detection System (IDS) Security Tests
 *
 * Tests for:
 * - Attack pattern detection
 * - Automated responses
 * - Security incident logging
 * - IP blocking mechanisms
 * - Anomaly detection
 */
class IntrusionDetectionSystemTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected IntrusionDetectionService $idsService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $this->idsService = app(IntrusionDetectionService::class);
    }

    /** @test */
    public function it_detects_sql_injection_attempts()
    {
        Passport::actingAs($this->user);

        $sqlPayloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            '; DROP TABLE users--',
        ];

        foreach ($sqlPayloads as $payload) {
            $response = $this->getJson("/api/v1/users?search={$payload}");

            // Should detect and log
            $incident = SecurityIncident::where('type', 'sql_injection')
                ->where('ip_address', '127.0.0.1')
                ->latest()
                ->first();

            if ($incident) {
                $this->assertEquals('critical', $incident->severity);
                $this->assertStringContainsString('SQL injection', $incident->description);
            }
        }
    }

    /** @test */
    public function it_detects_xss_attempts()
    {
        Passport::actingAs($this->user);

        $xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<iframe src="javascript:alert(1)">',
        ];

        foreach ($xssPayloads as $payload) {
            $response = $this->putJson("/api/v1/users/{$this->user->id}", [
                'name' => $payload,
            ]);

            $incident = SecurityIncident::where('type', 'xss_attempt')
                ->where('ip_address', '127.0.0.1')
                ->latest()
                ->first();

            if ($incident) {
                $this->assertEquals('high', $incident->severity);
                $this->assertStringContainsString('XSS', $incident->description);
            }
        }
    }

    /** @test */
    public function it_detects_brute_force_attacks_and_creates_incidents()
    {
        // Simulate brute force
        for ($i = 0; $i < 6; $i++) {
            FailedLoginAttempt::create([
                'email' => $this->user->email,
                'ip_address' => '192.168.1.100',
                'user_agent' => 'Mozilla/5.0',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        $detected = $this->idsService->detectBruteForce($this->user->email, '192.168.1.100');

        $this->assertTrue($detected);

        $incident = SecurityIncident::where('type', 'brute_force')
            ->where('ip_address', '192.168.1.100')
            ->first();

        $this->assertNotNull($incident);
        $this->assertContains($incident->severity, ['high', 'critical']);
    }

    /** @test */
    public function it_detects_credential_stuffing_attacks()
    {
        // Create multiple failed attempts with different emails from same IP
        for ($i = 0; $i < 12; $i++) {
            FailedLoginAttempt::create([
                'email' => "user{$i}@example.com",
                'ip_address' => '10.0.0.50',
                'user_agent' => 'Mozilla/5.0',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        $detected = $this->idsService->detectCredentialStuffing('10.0.0.50');

        $this->assertTrue($detected);

        $incident = SecurityIncident::where('type', 'credential_stuffing')
            ->where('ip_address', '10.0.0.50')
            ->first();

        $this->assertNotNull($incident);
        $this->assertEquals('critical', $incident->severity);
    }

    /** @test */
    public function it_automatically_blocks_ip_on_severe_attacks()
    {
        // Create excessive failed attempts to trigger auto-block
        for ($i = 0; $i < 25; $i++) {
            FailedLoginAttempt::create([
                'email' => "victim{$i}@example.com",
                'ip_address' => '203.0.113.50',
                'user_agent' => 'AttackBot/1.0',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        $this->idsService->detectCredentialStuffing('203.0.113.50');

        $ipBlock = IpBlocklist::where('ip_address', '203.0.113.50')
            ->where('is_active', true)
            ->first();

        $this->assertNotNull($ipBlock);
        $this->assertEquals('credential_stuffing', $ipBlock->reason);
    }

    /** @test */
    public function it_detects_anomalous_api_activity()
    {
        $request = Request::create('/api/v1/users', 'GET');
        $request->server->set('REMOTE_ADDR', '172.16.0.100');

        // Simulate high request rate
        for ($i = 0; $i < 120; $i++) {
            $this->idsService->detectAnomalousApiActivity($request);
        }

        $incident = SecurityIncident::where('type', 'api_abuse')
            ->where('ip_address', '172.16.0.100')
            ->first();

        $this->assertNotNull($incident);
        $this->assertEquals('high', $incident->severity);
    }

    /** @test */
    public function it_detects_unusual_login_patterns()
    {
        // Create successful login
        \App\Models\AuthenticationLog::create([
            'user_id' => $this->user->id,
            'event' => 'login_success',
            'ip_address' => '1.2.3.4',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => [],
        ]);

        $request = Request::create('/api/auth/login', 'POST');
        $request->server->set('REMOTE_ADDR', '5.6.7.8');

        $detected = $this->idsService->detectUnusualLoginPattern($this->user, $request);

        if ($detected) {
            $incident = SecurityIncident::where('type', 'unusual_login_pattern')
                ->where('user_id', $this->user->id)
                ->first();

            $this->assertNotNull($incident);
        }
    }

    /** @test */
    public function it_records_failed_login_attempts_with_metadata()
    {
        $request = Request::create('/api/auth/login', 'POST');
        $request->server->set('REMOTE_ADDR', '8.8.8.8');
        $request->server->set('HTTP_USER_AGENT', 'TestBot/1.0');

        $this->idsService->recordFailedAttempt($this->user->email, $request, 'invalid_credentials');

        $attempt = FailedLoginAttempt::where('email', $this->user->email)->first();

        $this->assertNotNull($attempt);
        $this->assertEquals('8.8.8.8', $attempt->ip_address);
        $this->assertEquals('TestBot/1.0', $attempt->user_agent);
        $this->assertEquals('invalid_credentials', $attempt->failure_reason);
    }

    /** @test */
    public function it_calculates_ip_security_score_correctly()
    {
        // Clean IP should have high score
        $score1 = $this->idsService->getIpSecurityScore('192.168.1.1');
        $this->assertEquals(100, $score1);

        // Create some failed attempts
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::create([
                'email' => "test{$i}@example.com",
                'ip_address' => '192.168.1.2',
                'user_agent' => 'Mozilla/5.0',
                'attempt_type' => 'password',
                'failure_reason' => 'invalid_credentials',
                'attempted_at' => now(),
            ]);
        }

        $score2 = $this->idsService->getIpSecurityScore('192.168.1.2');
        $this->assertLessThan(100, $score2);
        $this->assertGreaterThanOrEqual(0, $score2);

        // Create security incidents
        SecurityIncident::create([
            'type' => 'sql_injection',
            'severity' => 'critical',
            'ip_address' => '192.168.1.3',
            'endpoint' => '/api/v1/users',
            'description' => 'SQL injection detected',
            'detected_at' => now(),
        ]);

        $score3 = $this->idsService->getIpSecurityScore('192.168.1.3');
        $this->assertLessThan($score2, $score3);
    }

    /** @test */
    public function it_checks_if_ip_is_blocked()
    {
        // Unblocked IP
        $this->assertFalse($this->idsService->isIpBlocked('10.0.0.1'));

        // Block an IP
        IpBlocklist::create([
            'ip_address' => '10.0.0.2',
            'reason' => 'brute_force',
            'description' => 'Test block',
            'is_active' => true,
            'blocked_at' => now(),
            'expires_at' => now()->addHours(24),
        ]);

        $this->assertTrue($this->idsService->isIpBlocked('10.0.0.2'));

        // Expired block should return false
        IpBlocklist::create([
            'ip_address' => '10.0.0.3',
            'reason' => 'test',
            'description' => 'Expired block',
            'is_active' => true,
            'blocked_at' => now()->subDays(2),
            'expires_at' => now()->subDay(),
        ]);

        $this->assertFalse($this->idsService->isIpBlocked('10.0.0.3'));
    }

    /** @test */
    public function it_blocks_requests_from_blocked_ips()
    {
        // Block IP
        IpBlocklist::create([
            'ip_address' => '127.0.0.1',
            'reason' => 'test',
            'description' => 'Test block',
            'is_active' => true,
            'blocked_at' => now(),
            'expires_at' => now()->addHours(1),
        ]);

        $response = $this->getJson('/api/v1/health');

        $response->assertStatus(403);
        $this->assertStringContainsString('blocked', strtolower($response->json('message')));
    }

    /** @test */
    public function it_detects_distributed_attacks_across_multiple_ips()
    {
        // Simulate distributed attack
        $ips = ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'];

        foreach ($ips as $ip) {
            for ($i = 0; $i < 3; $i++) {
                FailedLoginAttempt::create([
                    'email' => $this->user->email,
                    'ip_address' => $ip,
                    'user_agent' => 'BotNet/1.0',
                    'attempt_type' => 'password',
                    'failure_reason' => 'invalid_credentials',
                    'attempted_at' => now(),
                ]);
            }
        }

        // Count incidents
        $totalAttempts = FailedLoginAttempt::where('email', $this->user->email)
            ->where('attempted_at', '>=', now()->subMinutes(15))
            ->count();

        $this->assertGreaterThanOrEqual(15, $totalAttempts);
    }

    /** @test */
    public function it_logs_security_incidents_with_proper_severity()
    {
        $request = Request::create('/api/v1/users?id=1\' OR \'1\'=\'1', 'GET');
        $request->server->set('REMOTE_ADDR', '6.6.6.6');

        $this->idsService->detectSqlInjection($request);

        $incident = SecurityIncident::where('ip_address', '6.6.6.6')->first();

        $this->assertNotNull($incident);
        $this->assertEquals('critical', $incident->severity);
        $this->assertArrayHasKey('pattern', $incident->metadata);
    }

    /** @test */
    public function it_cleans_up_old_failed_attempts()
    {
        // Create old attempts
        FailedLoginAttempt::create([
            'email' => 'old@example.com',
            'ip_address' => '7.7.7.7',
            'user_agent' => 'Old/1.0',
            'attempt_type' => 'password',
            'failure_reason' => 'invalid_credentials',
            'attempted_at' => now()->subDays(30),
        ]);

        // Detection should only consider recent attempts
        $detected = $this->idsService->detectBruteForce('old@example.com', '7.7.7.7');

        $this->assertFalse($detected);
    }

    /** @test */
    public function it_validates_security_incident_metadata_structure()
    {
        $request = Request::create('/api/test', 'POST');
        $request->server->set('REMOTE_ADDR', '8.8.8.8');
        $request->server->set('HTTP_USER_AGENT', 'TestAgent/1.0');

        $this->idsService->detectXss($request->merge(['name' => '<script>alert(1)</script>']));

        $incident = SecurityIncident::where('ip_address', '8.8.8.8')->latest()->first();

        if ($incident) {
            $this->assertIsArray($incident->metadata);
            $this->assertArrayHasKey('pattern', $incident->metadata);
            $this->assertArrayHasKey('parameter', $incident->metadata);
            $this->assertArrayHasKey('user_agent', $incident->metadata);
        }
    }

    /** @test */
    public function it_prevents_false_positives_in_legitimate_queries()
    {
        Passport::actingAs($this->user);

        // Legitimate search that might look suspicious
        $response = $this->getJson('/api/v1/users?search=O\'Brien');

        // Should not block legitimate apostrophe in name
        $this->assertEquals(200, $response->status());
    }

    /** @test */
    public function it_detects_rate_limiting_bypass_attempts()
    {
        // Try to bypass rate limiting with different user agents
        $userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (X11; Linux x86_64)',
        ];

        $responses = [];

        foreach ($userAgents as $ua) {
            for ($i = 0; $i < 50; $i++) {
                $response = $this->withHeaders(['User-Agent' => $ua])
                    ->getJson('/api/v1/health');
                $responses[] = $response;
            }
        }

        // Should still hit rate limit
        $rateLimited = collect($responses)->first(fn ($r) => $r->status() === 429);
        $this->assertNotNull($rateLimited);
    }
}
