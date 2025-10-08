<?php

namespace Tests\Unit\Services\Security;

use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\SecurityIncident;
use App\Models\User;
use App\Services\Security\AccountLockoutService;
use App\Services\Security\IntrusionDetectionService;
use App\Services\Security\IpBlocklistService;
use App\Services\Security\SecurityIncidentService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class IntrusionDetectionServiceTest extends TestCase
{
    private IntrusionDetectionService $service;

    private SecurityIncidentService $incidentService;

    private IpBlocklistService $ipBlocklistService;

    private AccountLockoutService $lockoutService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->incidentService = $this->createMock(SecurityIncidentService::class);
        $this->ipBlocklistService = $this->createMock(IpBlocklistService::class);
        $this->lockoutService = $this->createMock(AccountLockoutService::class);

        $this->service = new IntrusionDetectionService(
            $this->incidentService,
            $this->ipBlocklistService,
            $this->lockoutService
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_brute_force_attack_by_email(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        // Create 6 failed attempts (above threshold of 5)
        for ($i = 0; $i < 6; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => $email,
                'ip_address' => $ipAddress,
                'attempted_at' => now()->subMinutes(5),
            ]);
        }

        Config::set('security.brute_force.email_threshold', 5);
        Config::set('security.brute_force.ip_threshold', 10);

        $this->incidentService->expects($this->once())
            ->method('createIncident')
            ->with($this->callback(function ($data) {
                return $data['type'] === 'brute_force'
                    && $data['severity'] === 'high';
            }));

        $result = $this->service->detectBruteForce($email, $ipAddress);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_brute_force_attack_by_ip(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        // Create 11 failed attempts from same IP (above threshold of 10)
        for ($i = 0; $i < 11; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => "user{$i}@example.com",
                'ip_address' => $ipAddress,
                'attempted_at' => now()->subMinutes(5),
            ]);
        }

        Config::set('security.brute_force.email_threshold', 5);
        Config::set('security.brute_force.ip_threshold', 10);

        $this->incidentService->expects($this->once())
            ->method('createIncident');

        $result = $this->service->detectBruteForce($email, $ipAddress);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_auto_blocks_ip_on_severe_brute_force(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        // Create 21 failed attempts (above 2x threshold)
        for ($i = 0; $i < 21; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => "user{$i}@example.com",
                'ip_address' => $ipAddress,
                'attempted_at' => now()->subMinutes(5),
            ]);
        }

        Config::set('security.brute_force.ip_threshold', 10);

        $this->incidentService->method('createIncident');

        $this->ipBlocklistService->expects($this->once())
            ->method('blockIp')
            ->with($ipAddress, 'brute_force', $this->isType('string'));

        $this->service->detectBruteForce($email, $ipAddress);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_detect_brute_force_below_threshold(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        // Create only 3 failed attempts (below threshold)
        for ($i = 0; $i < 3; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => $email,
                'ip_address' => $ipAddress,
                'attempted_at' => now()->subMinutes(5),
            ]);
        }

        Config::set('security.brute_force.email_threshold', 5);

        $this->incidentService->expects($this->never())
            ->method('createIncident');

        $result = $this->service->detectBruteForce($email, $ipAddress);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_credential_stuffing_attack(): void
    {
        $ipAddress = '192.168.1.1';

        // Create attempts for 11 unique emails in 5 minutes (above threshold)
        for ($i = 0; $i < 11; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => "user{$i}@example.com",
                'ip_address' => $ipAddress,
                'attempted_at' => now()->subMinutes(2),
            ]);
        }

        Config::set('security.credential_stuffing.threshold', 10);

        $this->incidentService->expects($this->once())
            ->method('createIncident')
            ->with($this->callback(function ($data) {
                return $data['type'] === 'credential_stuffing'
                    && $data['severity'] === 'critical';
            }));

        $this->ipBlocklistService->expects($this->once())
            ->method('blockIp')
            ->with($ipAddress, 'credential_stuffing');

        $result = $this->service->detectCredentialStuffing($ipAddress);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_detect_credential_stuffing_below_threshold(): void
    {
        $ipAddress = '192.168.1.1';

        // Create attempts for only 5 unique emails
        for ($i = 0; $i < 5; $i++) {
            FailedLoginAttempt::factory()->create([
                'email' => "user{$i}@example.com",
                'ip_address' => $ipAddress,
                'attempted_at' => now()->subMinutes(2),
            ]);
        }

        Config::set('security.credential_stuffing.threshold', 10);

        $this->incidentService->expects($this->never())
            ->method('createIncident');

        $result = $this->service->detectCredentialStuffing($ipAddress);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_anomalous_api_activity(): void
    {
        $ipAddress = '192.168.1.1';

        $request = Request::create('/api/test', 'GET');
        $request->server->set('REMOTE_ADDR', $ipAddress);

        Config::set('security.api_rate.anomaly_threshold', 10);

        // Simulate 15 requests in cache (above threshold)
        $timestamps = [];
        for ($i = 0; $i < 15; $i++) {
            $timestamps[] = now()->timestamp;
        }
        Cache::shouldReceive('get')->andReturn($timestamps);
        Cache::shouldReceive('put')->once();

        $this->incidentService->expects($this->once())
            ->method('createIncident')
            ->with($this->callback(function ($data) {
                return $data['type'] === 'api_abuse' && $data['severity'] === 'high';
            }));

        $result = $this->service->detectAnomalousApiActivity($request);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_sql_injection_attempts(): void
    {
        $request = Request::create('/api/search', 'GET', [
            'query' => "'; DROP TABLE users; --",
        ]);

        $this->incidentService->expects($this->once())
            ->method('createIncident')
            ->with($this->callback(function ($data) {
                return $data['type'] === 'sql_injection'
                    && $data['severity'] === 'critical';
            }));

        $result = $this->service->detectSqlInjection($request);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('sqlInjectionProvider')]
    public function it_detects_various_sql_injection_patterns(string $maliciousInput): void
    {
        $request = Request::create('/api/test', 'GET', [
            'param' => $maliciousInput,
        ]);

        $this->incidentService->expects($this->once())
            ->method('createIncident');

        $result = $this->service->detectSqlInjection($request);

        $this->assertTrue($result);
    }

    public static function sqlInjectionProvider(): array
    {
        return [
            'OR condition' => ["1' OR '1'='1"],
            'UNION SELECT' => ['UNION SELECT * FROM users'],
            'DROP TABLE' => ['DROP TABLE users'],
            'SQL comments' => ["admin'--"],
            'INSERT INTO' => ['INSERT INTO users VALUES'],
            'UPDATE SET' => ['UPDATE users SET password'],
            'EXEC command' => ['EXEC sp_executesql'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_xss_attempts(): void
    {
        $request = Request::create('/api/comment', 'POST', [
            'comment' => '<script>alert("XSS")</script>',
        ]);

        $this->incidentService->expects($this->once())
            ->method('createIncident')
            ->with($this->callback(function ($data) {
                return $data['type'] === 'xss_attempt' && $data['severity'] === 'high';
            }));

        $result = $this->service->detectXss($request);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('xssProvider')]
    public function it_detects_various_xss_patterns(string $maliciousInput): void
    {
        $request = Request::create('/api/test', 'POST', [
            'content' => $maliciousInput,
        ]);

        $this->incidentService->expects($this->once())
            ->method('createIncident');

        $result = $this->service->detectXss($request);

        $this->assertTrue($result);
    }

    public static function xssProvider(): array
    {
        return [
            'script tag' => ['<script>alert(1)</script>'],
            'javascript protocol' => ['<a href="javascript:alert(1)">click</a>'],
            'onerror handler' => ['<img src=x onerror=alert(1)>'],
            'onload handler' => ['<body onload=alert(1)>'],
            'iframe tag' => ['<iframe src="evil.com"></iframe>'],
            'embed tag' => ['<embed src="evil.swf">'],
            'object tag' => ['<object data="evil.swf">'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_unusual_login_pattern_different_ip(): void
    {
        $user = User::factory()->create();

        // Create recent login from different IP
        $user->authenticationLogs()->create([
            'event' => 'login_success',
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => now()->subMinutes(30),
        ]);

        $request = Request::create('/login', 'POST');
        $request->server->set('REMOTE_ADDR', '10.0.0.1'); // Different IP

        $this->incidentService->expects($this->once())
            ->method('createIncident')
            ->with($this->callback(function ($data) {
                return $data['type'] === 'unusual_login_pattern'
                    && $data['severity'] === 'medium';
            }));

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $result = $this->service->detectUnusualLoginPattern($user, $request);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_detect_unusual_pattern_same_ip(): void
    {
        $user = User::factory()->create();
        $ipAddress = '192.168.1.1';

        $user->authenticationLogs()->create([
            'event' => 'login_success',
            'ip_address' => $ipAddress,
            'user_agent' => 'Mozilla/5.0',
            'created_at' => now()->subMinutes(30),
        ]);

        $request = Request::create('/login', 'POST');
        $request->server->set('REMOTE_ADDR', $ipAddress);

        $this->incidentService->expects($this->never())
            ->method('createIncident');

        $result = $this->service->detectUnusualLoginPattern($user, $request);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_records_failed_login_attempt(): void
    {
        $email = 'test@example.com';
        $ipAddress = '192.168.1.1';

        $request = Request::create('/login', 'POST');
        $request->server->set('REMOTE_ADDR', $ipAddress);

        Config::set('security.brute_force.email_threshold', 100); // High threshold to avoid detection

        $this->service->recordFailedAttempt($email, $request, 'invalid_password');

        $this->assertDatabaseHas('failed_login_attempts', [
            'email' => $email,
            'ip_address' => $ipAddress,
            'failure_reason' => 'invalid_password',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_if_ip_is_blocked(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
            'expires_at' => now()->addHours(24),
        ]);

        $result = $this->service->isIpBlocked($ipAddress);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_ip_not_blocked_when_expired(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
            'expires_at' => now()->subHours(1), // Expired
        ]);

        $result = $this->service->isIpBlocked($ipAddress);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calculates_ip_security_score(): void
    {
        $ipAddress = '192.168.1.1';

        // Create some failed attempts
        FailedLoginAttempt::factory()->count(3)->create([
            'ip_address' => $ipAddress,
            'attempted_at' => now()->subHours(12),
        ]);

        // Create security incidents
        SecurityIncident::factory()->count(2)->create([
            'ip_address' => $ipAddress,
            'detected_at' => now()->subDays(3),
        ]);

        // Create IP blocks
        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'blocked_at' => now()->subDays(15),
        ]);

        $score = $this->service->getIpSecurityScore($ipAddress);

        // Score should be less than 100 due to violations
        $this->assertLessThan(100, $score);
        $this->assertGreaterThanOrEqual(0, $score);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_perfect_score_for_clean_ip(): void
    {
        $ipAddress = '192.168.1.1';

        $score = $this->service->getIpSecurityScore($ipAddress);

        $this->assertEquals(100, $score);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_detect_safe_input(): void
    {
        $request = Request::create('/api/search', 'GET', [
            'query' => 'normal search query',
            'email' => 'user@example.com',
        ]);

        $this->incidentService->expects($this->never())
            ->method('createIncident');

        $sqlResult = $this->service->detectSqlInjection($request);
        $xssResult = $this->service->detectXss($request);

        $this->assertFalse($sqlResult);
        $this->assertFalse($xssResult);
    }
}
