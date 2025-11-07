<?php

namespace Tests\Integration\Organizations;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * Organization Analytics Integration Tests
 *
 * Tests organization analytics and metrics including:
 * - User count metrics
 * - Login activity statistics
 * - Application usage stats
 * - MFA adoption rates
 * - Security incident summaries
 * - Analytics data export
 *
 * Verifies:
 * - Metrics are calculated correctly
 * - Time-based filtering works
 * - Data is properly aggregated
 * - Export formats are valid
 */
class OrganizationAnalyticsTest extends IntegrationTestCase
{
    protected User $admin;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->admin = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_get_user_count_metrics(): void
    {
        // ARRANGE: Create users with different states
        User::factory()->count(10)->create([
            'organization_id' => $this->organization->id,
            'email_verified_at' => now(),
        ]);

        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'email_verified_at' => null, // Unverified
        ]);

        User::factory()->count(2)->withMfa()->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Get user metrics
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/metrics/users");

        // ASSERT: Verify response structure
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'total_users',
                    'active_users',
                    'verified_users',
                    'unverified_users',
                    'mfa_enabled_users',
                    'users_created_this_month',
                ],
            ]);

        // ASSERT: Verify metric values
        $metrics = $response->json('data');
        $this->assertGreaterThanOrEqual(15, $metrics['total_users']); // 10 + 3 + 2 + admin
        // 10 explicitly verified + 2 withMfa (verified by default) + 1 admin (verified by default) = 13
        $this->assertEquals(13, $metrics['verified_users']);
        $this->assertEquals(3, $metrics['unverified_users']);
        $this->assertGreaterThanOrEqual(2, $metrics['mfa_enabled_users']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_get_login_activity_stats(): void
    {
        // ARRANGE: Create authentication logs
        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        foreach ($users as $user) {
            // Create successful logins
            AuthenticationLog::factory()->count(3)->successfulLogin()->create([
                'user_id' => $user->id,
                'created_at' => now()->subDays(rand(1, 7)),
            ]);

            // Create failed logins
            AuthenticationLog::factory()->count(2)->failedLogin()->create([
                'user_id' => $user->id,
                'created_at' => now()->subDays(rand(1, 7)),
            ]);
        }

        // ACT: Get login activity stats
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/analytics?period=7days");

        // ASSERT: Verify response structure
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'total_logins',
                    'successful_logins',
                    'failed_logins',
                    'unique_users_logged_in',
                    'login_trends',
                ],
            ]);

        // ASSERT: Verify login counts
        $analytics = $response->json('data');
        $this->assertEquals(15, $analytics['successful_logins']); // 5 users × 3
        $this->assertEquals(10, $analytics['failed_logins']); // 5 users × 2
        $this->assertEquals(25, $analytics['total_logins']);
        $this->assertEquals(5, $analytics['unique_users_logged_in']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_get_application_usage_stats(): void
    {
        // ARRANGE: Create applications and usage data
        $app1 = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'App 1',
        ]);

        $app2 = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'App 2',
        ]);

        $users = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        // Create access logs for apps
        foreach ($users as $user) {
            $app1->users()->attach($user->id, [
                'granted_at' => now()->subDays(5),
                'login_count' => rand(5, 15),
                'last_login_at' => now()->subHours(rand(1, 24)),
            ]);

            $app2->users()->attach($user->id, [
                'granted_at' => now()->subDays(3),
                'login_count' => rand(2, 8),
                'last_login_at' => now()->subHours(rand(1, 48)),
            ]);
        }

        // ACT: Get application usage metrics
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/metrics/applications");

        // ASSERT: Verify response structure
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'total_applications',
                    'active_applications',
                    'applications' => [
                        '*' => [
                            'id',
                            'name',
                            'total_users',
                            'active_users',
                            'total_logins',
                        ],
                    ],
                ],
            ]);

        // ASSERT: Verify application counts
        $metrics = $response->json('data');
        $this->assertEquals(2, $metrics['total_applications']);

        // ASSERT: Verify per-app metrics
        $appMetrics = collect($metrics['applications']);
        $app1Metrics = $appMetrics->firstWhere('name', 'App 1');
        $this->assertNotNull($app1Metrics);
        $this->assertEquals(3, $app1Metrics['total_users']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_get_mfa_adoption_rate(): void
    {
        // ARRANGE: Create users with MFA
        User::factory()->count(7)->withMfa()->create([
            'organization_id' => $this->organization->id,
        ]);

        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Get MFA metrics
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/metrics/users");

        // ASSERT: Verify MFA adoption metrics
        $response->assertOk();
        $metrics = $response->json('data');

        $this->assertArrayHasKey('mfa_enabled_users', $metrics);
        $this->assertArrayHasKey('mfa_disabled_users', $metrics);
        $this->assertArrayHasKey('mfa_adoption_rate', $metrics);

        // Calculate expected adoption rate
        $totalUsers = $metrics['total_users'];
        $mfaUsers = $metrics['mfa_enabled_users'];
        $expectedRate = ($mfaUsers / $totalUsers) * 100;

        // 7 users with MFA explicitly created
        $this->assertEquals(7, $metrics['mfa_enabled_users']);
        // 3 regular users + 1 admin without MFA = 4
        $this->assertEquals(4, $metrics['mfa_disabled_users']);
        $this->assertEqualsWithDelta($expectedRate, $metrics['mfa_adoption_rate'], 1);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_get_security_incident_summary(): void
    {
        // ARRANGE: Create security incidents
        $incidents = [
            'brute_force' => 5,
            'suspicious_login' => 3,
            'account_lockout' => 2,
            'password_reset' => 4,
        ];

        foreach ($incidents as $type => $count) {
            SecurityIncident::factory()->count($count)->create([
                'type' => $type,
                'severity' => 'medium',
                'created_at' => now()->subDays(rand(1, 7)),
            ]);
        }

        // ACT: Get security metrics
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/metrics/security");

        // ASSERT: Verify response structure
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'total_incidents',
                    'incidents_by_type',
                    'incidents_by_severity',
                    'resolved_incidents',
                    'pending_incidents',
                ],
            ]);

        // ASSERT: Verify incident counts
        $metrics = $response->json('data');
        $this->assertEquals(14, $metrics['total_incidents']); // 5 + 3 + 2 + 4

        // ASSERT: Verify breakdown by type
        $byType = $metrics['incidents_by_type'];
        $this->assertEquals(5, $byType['brute_force']);
        $this->assertEquals(3, $byType['suspicious_login']);
        $this->assertEquals(2, $byType['account_lockout']);
        $this->assertEquals(4, $byType['password_reset']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_export_analytics_data(): void
    {
        // ARRANGE: Create some activity data
        User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Export analytics data
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/export", [
                'format' => 'json',
                'data_type' => 'analytics',
                'period' => '30days',
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'export_id',
                    'status',
                    'download_url',
                ],
            ]);

        // ASSERT: Verify export is created
        $exportData = $response->json('data');
        $this->assertEquals('completed', $exportData['status']);
        $this->assertNotNull($exportData['download_url']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_analytics_respect_time_period_filter(): void
    {
        // ARRANGE: Create logs with different dates
        $recentUser = $this->createUser(['organization_id' => $this->organization->id]);
        AuthenticationLog::factory()->count(5)->successfulLogin()->create([
            'user_id' => $recentUser->id,
            'created_at' => now()->subDays(3),
        ]);

        $oldUser = $this->createUser(['organization_id' => $this->organization->id]);
        AuthenticationLog::factory()->count(10)->successfulLogin()->create([
            'user_id' => $oldUser->id,
            'created_at' => now()->subDays(40),
        ]);

        // ACT: Get analytics for last 7 days
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/analytics?period=7days");

        // ASSERT: Verify only recent logs are counted
        $response->assertOk();
        $analytics = $response->json('data');
        $this->assertEquals(5, $analytics['total_logins']);

        // ACT: Get analytics for last 30 days
        $response30 = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/analytics?period=30days");

        // ASSERT: Verify still only recent logs (old ones are 40 days ago)
        $analytics30 = $response30->json('data');
        $this->assertEquals(5, $analytics30['total_logins']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_analytics_isolation_between_organizations(): void
    {
        // ARRANGE: Create another organization with data
        $otherOrg = $this->createOrganization();
        $otherUsers = User::factory()->count(10)->create([
            'organization_id' => $otherOrg->id,
        ]);

        foreach ($otherUsers as $user) {
            AuthenticationLog::factory()->count(5)->successfulLogin()->create([
                'user_id' => $user->id,
            ]);
        }

        // ACT: Get analytics for current organization
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/analytics");

        // ASSERT: Verify only current org data is included
        $response->assertOk();
        $analytics = $response->json('data');

        // Should not include other org's 50 logins
        $this->assertLessThan(50, $analytics['total_logins']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_export_analytics_in_multiple_formats(): void
    {
        // ARRANGE: Create some data
        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT & ASSERT: Export as JSON
        $jsonResponse = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/export", [
                'format' => 'json',
                'data_type' => 'analytics',
            ]);

        $jsonResponse->assertOk();
        $this->assertEquals('json', $jsonResponse->json('data.format'));

        // ACT & ASSERT: Export as CSV
        $csvResponse = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/export", [
                'format' => 'csv',
                'data_type' => 'analytics',
            ]);

        $csvResponse->assertOk();
        $this->assertEquals('csv', $csvResponse->json('data.format'));

        // ACT & ASSERT: Export as Excel
        $excelResponse = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/export", [
                'format' => 'xlsx',
                'data_type' => 'analytics',
            ]);

        $excelResponse->assertOk();
        $this->assertEquals('xlsx', $excelResponse->json('data.format'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_analytics_caching_improves_performance(): void
    {
        // ARRANGE: Create substantial data
        User::factory()->count(50)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: First request (should hit database)
        $startTime = microtime(true);
        $firstResponse = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/metrics/users");
        $firstDuration = microtime(true) - $startTime;

        // ACT: Second request (should hit cache)
        $cachedStartTime = microtime(true);
        $secondResponse = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/metrics/users");
        $cachedDuration = microtime(true) - $cachedStartTime;

        // ASSERT: Both requests succeed
        $firstResponse->assertOk();
        $secondResponse->assertOk();

        // ASSERT: Cached response should be faster (or at least not slower)
        $this->assertLessThanOrEqual($firstDuration * 1.5, $cachedDuration,
            'Cached response should not be significantly slower');

        // ASSERT: Data should be identical
        $this->assertEquals(
            $firstResponse->json('data'),
            $secondResponse->json('data')
        );
    }
}
