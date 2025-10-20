<?php

namespace Tests\Unit\Services\Security;

use App\Models\SecurityIncident;
use App\Models\User;
use App\Services\Security\SecurityIncidentService;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class SecurityIncidentServiceTest extends TestCase
{
    private SecurityIncidentService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new SecurityIncidentService;
    }

    protected function tearDown(): void
    {
        // Clean up Mockery expectations to prevent "risky" test warnings
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_security_incident(): void
    {
        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('error');

        $data = [
            'type' => 'brute_force',
            'severity' => 'high',
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'endpoint' => '/api/auth/login',
            'description' => 'Brute force attack detected',
            'metadata' => ['attempts' => 10],
        ];

        $incident = $this->service->createIncident($data);

        $this->assertInstanceOf(SecurityIncident::class, $incident);
        $this->assertEquals('brute_force', $incident->type);
        $this->assertEquals('high', $incident->severity);
        $this->assertEquals('192.168.1.1', $incident->ip_address);
        $this->assertEquals('open', $incident->status);
        $this->assertNotNull($incident->detected_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_incident_with_user_id(): void
    {
        $user = User::factory()->create();

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $data = [
            'type' => 'unusual_login_pattern',
            'severity' => 'medium',
            'ip_address' => '192.168.1.1',
            'user_id' => $user->id,
            'description' => 'Unusual login pattern detected',
        ];

        $incident = $this->service->createIncident($data);

        $this->assertEquals($user->id, $incident->user_id);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('severityLogLevelProvider')]
    public function it_logs_incidents_with_appropriate_level(string $severity, string $expectedLogLevel): void
    {
        // Create Super Admin role if severity is critical (needed for admin notification)
        if ($severity === 'critical') {
            \Spatie\Permission\Models\Role::create(['name' => 'Super Admin', 'guard_name' => 'web']);
        }

        Log::shouldReceive('channel')->andReturnSelf();
        // Critical severity logs twice: once for incident, once for admin notification
        if ($severity === 'critical') {
            Log::shouldReceive($expectedLogLevel)->twice();
        } else {
            Log::shouldReceive($expectedLogLevel)->once();
        }

        $data = [
            'type' => 'test_incident',
            'severity' => $severity,
            'ip_address' => '192.168.1.1',
            'description' => 'Test incident',
        ];

        $incident = $this->service->createIncident($data);

        // Verify the incident was created with correct severity
        $this->assertEquals($severity, $incident->severity);
    }

    public static function severityLogLevelProvider(): array
    {
        return [
            'critical severity' => ['critical', 'critical'],
            'high severity' => ['high', 'error'],
            'medium severity' => ['medium', 'warning'],
            'low severity' => ['low', 'info'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_notifies_admins_for_critical_incidents(): void
    {
        // Create Super Admin role
        $role = \Spatie\Permission\Models\Role::create(['name' => 'Super Admin', 'guard_name' => 'web']);

        // Create super admins
        $admin1 = User::factory()->create();
        $admin2 = User::factory()->create();
        $admin1->assignRole($role);
        $admin2->assignRole($role);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('critical')->twice(); // Once for incident, once for notification

        $data = [
            'type' => 'sql_injection',
            'severity' => 'critical',
            'ip_address' => '192.168.1.1',
            'description' => 'SQL injection attempt detected',
        ];

        $incident = $this->service->createIncident($data);

        // Assert incident was created with critical severity
        $this->assertInstanceOf(SecurityIncident::class, $incident);
        $this->assertEquals('critical', $incident->severity);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_notify_for_non_critical_incidents(): void
    {
        // Create Super Admin role
        $role = \Spatie\Permission\Models\Role::create(['name' => 'Super Admin', 'guard_name' => 'web']);

        $admin = User::factory()->create();
        $admin->assignRole($role);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('error')->once();
        Log::shouldReceive('critical')->never();

        $data = [
            'type' => 'api_abuse',
            'severity' => 'high',
            'ip_address' => '192.168.1.1',
            'description' => 'High rate of API requests',
        ];

        $incident = $this->service->createIncident($data);

        // Assert incident was created but not at critical level
        $this->assertInstanceOf(SecurityIncident::class, $incident);
        $this->assertEquals('high', $incident->severity);
        $this->assertNotEquals('critical', $incident->severity);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_resolves_incident(): void
    {
        $incident = SecurityIncident::factory()->create([
            'status' => 'open',
        ]);

        $resolvedBy = User::factory()->create();

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info');

        $result = $this->service->resolveIncident(
            $incident->id,
            'Issue was investigated and resolved',
            $resolvedBy
        );

        $this->assertTrue($result);

        $incident->refresh();
        $this->assertEquals('resolved', $incident->status);
        $this->assertNotNull($incident->resolved_at);
        $this->assertEquals('Issue was investigated and resolved', $incident->resolution_notes);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_false_when_resolving_non_existent_incident(): void
    {
        $resolvedBy = User::factory()->create();

        $result = $this->service->resolveIncident(
            99999,
            'Resolution notes',
            $resolvedBy
        );

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_open_incidents(): void
    {
        SecurityIncident::factory()->count(3)->create([
            'status' => 'open',
            'severity' => 'high',
        ]);

        SecurityIncident::factory()->count(2)->create([
            'status' => 'resolved',
            'severity' => 'high',
        ]);

        $openIncidents = $this->service->getOpenIncidents();

        $this->assertCount(3, $openIncidents);
        $this->assertTrue($openIncidents->every(fn ($i) => $i->status === 'open'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_filters_open_incidents_by_severity(): void
    {
        SecurityIncident::factory()->count(2)->create([
            'status' => 'open',
            'severity' => 'critical',
        ]);

        SecurityIncident::factory()->count(3)->create([
            'status' => 'open',
            'severity' => 'high',
        ]);

        $criticalIncidents = $this->service->getOpenIncidents('critical');

        $this->assertCount(2, $criticalIncidents);
        $this->assertTrue($criticalIncidents->every(fn ($i) => $i->severity === 'critical'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_orders_open_incidents_by_detected_at_desc(): void
    {
        $oldest = SecurityIncident::factory()->create([
            'status' => 'open',
            'detected_at' => now()->subDays(3),
        ]);

        $newest = SecurityIncident::factory()->create([
            'status' => 'open',
            'detected_at' => now(),
        ]);

        $middle = SecurityIncident::factory()->create([
            'status' => 'open',
            'detected_at' => now()->subDays(1),
        ]);

        $incidents = $this->service->getOpenIncidents();

        $this->assertEquals($newest->id, $incidents->first()->id);
        $this->assertEquals($oldest->id, $incidents->last()->id);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_incident_metrics(): void
    {
        // Open incidents
        SecurityIncident::factory()->count(2)->create([
            'status' => 'open',
            'severity' => 'critical',
            'detected_at' => now()->subHours(12),
        ]);

        SecurityIncident::factory()->count(3)->create([
            'status' => 'open',
            'severity' => 'high',
            'detected_at' => now()->subHours(6),
        ]);

        SecurityIncident::factory()->count(4)->create([
            'status' => 'resolved',
            'severity' => 'medium',
            'detected_at' => now()->subDays(3),
        ]);

        // Incidents by type (mark as resolved so they don't affect total_open count)
        SecurityIncident::factory()->create([
            'type' => 'brute_force',
            'status' => 'resolved',
            'detected_at' => now()->subDays(2),
        ]);

        SecurityIncident::factory()->create([
            'type' => 'brute_force',
            'status' => 'resolved',
            'detected_at' => now()->subDays(3),
        ]);

        SecurityIncident::factory()->create([
            'type' => 'sql_injection',
            'status' => 'resolved',
            'detected_at' => now()->subDays(4),
        ]);

        $metrics = $this->service->getIncidentMetrics();

        $this->assertEquals(5, $metrics['total_open']);
        $this->assertEquals(2, $metrics['critical_open']);
        $this->assertEquals(3, $metrics['high_open']);
        $this->assertGreaterThanOrEqual(5, $metrics['incidents_today']);
        $this->assertGreaterThanOrEqual(7, $metrics['incidents_this_week']);
        $this->assertArrayHasKey('by_type', $metrics);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_records_action_taken(): void
    {
        $incident = SecurityIncident::factory()->create([
            'action_taken' => null,
        ]);

        $result = $this->service->recordAction(
            $incident->id,
            'IP address was blocked'
        );

        $this->assertTrue($result);

        $incident->refresh();
        $this->assertEquals('IP address was blocked', $incident->action_taken);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_false_when_recording_action_for_non_existent_incident(): void
    {
        $result = $this->service->recordAction(99999, 'Action taken');

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_incident_with_metadata(): void
    {
        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('error');

        $metadata = [
            'attempts' => 15,
            'pattern' => 'UNION SELECT',
            'parameter' => 'search',
        ];

        $data = [
            'type' => 'sql_injection',
            'severity' => 'high',
            'ip_address' => '192.168.1.1',
            'description' => 'SQL injection attempt',
            'metadata' => $metadata,
        ];

        $incident = $this->service->createIncident($data);

        $this->assertEquals($metadata, $incident->metadata);
        $this->assertEquals(15, $incident->metadata['attempts']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_incident_without_optional_fields(): void
    {
        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $data = [
            'type' => 'api_abuse',
            'severity' => 'medium',
            'ip_address' => '192.168.1.1',
            'description' => 'API abuse detected',
        ];

        $incident = $this->service->createIncident($data);

        $this->assertNull($incident->user_agent);
        $this->assertNull($incident->endpoint);
        $this->assertNull($incident->user_id);
        $this->assertNull($incident->metadata);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('incidentTypeProvider')]
    public function it_creates_incidents_of_various_types(string $type, string $description): void
    {
        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('error');

        $data = [
            'type' => $type,
            'severity' => 'high',
            'ip_address' => '192.168.1.1',
            'description' => $description,
        ];

        $incident = $this->service->createIncident($data);

        $this->assertEquals($type, $incident->type);
        $this->assertEquals($description, $incident->description);
    }

    public static function incidentTypeProvider(): array
    {
        return [
            'brute force' => ['brute_force', 'Multiple failed login attempts'],
            'credential stuffing' => ['credential_stuffing', 'Testing leaked credentials'],
            'SQL injection' => ['sql_injection', 'SQL injection attempt detected'],
            'XSS attempt' => ['xss_attempt', 'Cross-site scripting detected'],
            'API abuse' => ['api_abuse', 'Excessive API requests'],
            'unusual login' => ['unusual_login_pattern', 'Login from unusual location'],
        ];
    }
}
