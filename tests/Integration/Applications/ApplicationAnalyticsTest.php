<?php

namespace Tests\Integration\Applications;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Token;
use Spatie\Permission\Models\Permission;
use Tests\Integration\IntegrationTestCase;

/**
 * Application Analytics Integration Tests
 *
 * Tests analytics and metrics endpoints for OAuth applications including:
 * - Token generation metrics over time periods
 * - API usage statistics and patterns
 * - User count and active user tracking
 * - Error rate analytics and failure patterns
 *
 * @covers \App\Http\Controllers\Api\ApplicationController::analytics
 */
class ApplicationAnalyticsTest extends IntegrationTestCase
{
    protected User $user;

    protected Organization $organization;

    protected Application $application;

    protected Client $passportClient;

    protected function setUp(): void
    {
        parent::setUp();

        // Create permissions if they don't exist
        Permission::firstOrCreate(['name' => 'applications.read', 'guard_name' => 'api']);

        $this->organization = $this->createOrganization();
        $this->user = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        // Create application with Passport client
        $this->passportClient = Client::create([
            'name' => 'Analytics Test App',
            'secret' => hash('sha256', 'test-secret'),
            'redirect' => 'https://app.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application = $this->createOAuthApplication([
            'name' => 'Analytics Test Application',
            'organization_id' => $this->organization->id,
            'client_id' => (string) Str::uuid(),
            'client_secret' => 'test-secret',
            'passport_client_id' => $this->passportClient->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_token_generation_metrics_over_time(): void
    {
        // ARRANGE: Create users and tokens with different timestamps
        $user1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user2 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user3 = $this->createApiUser(['organization_id' => $this->organization->id]);

        // Grant users access to application
        $this->application->users()->attach($user1->id, ['granted_at' => now()]);
        $this->application->users()->attach($user2->id, ['granted_at' => now()]);
        $this->application->users()->attach($user3->id, ['granted_at' => now()]);

        // Create active tokens (not expired)
        $activeToken1 = Token::create([
            'id' => Str::random(80),
            'user_id' => $user1->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Active Token 1',
            'scopes' => ['openid', 'profile'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHours(2),
            'created_at' => Carbon::now()->subHours(1),
        ]);

        $activeToken2 = Token::create([
            'id' => Str::random(80),
            'user_id' => $user2->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Active Token 2',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addMinutes(30),
            'created_at' => Carbon::now()->subMinutes(15),
        ]);

        // Create authentication logs for the last 7 days
        AuthenticationLog::create([
            'user_id' => $user1->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['method' => 'oauth'],
            'created_at' => Carbon::now()->subDays(1),
        ]);

        AuthenticationLog::create([
            'user_id' => $user2->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.101',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['method' => 'oauth'],
            'created_at' => Carbon::now()->subDays(2),
        ]);

        AuthenticationLog::create([
            'user_id' => $user1->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['method' => 'oauth'],
            'created_at' => Carbon::now()->subDays(3),
        ]);

        // Create failed login attempts
        AuthenticationLog::create([
            'user_id' => $user3->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_failed',
            'ip_address' => '192.168.1.102',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['reason' => 'invalid_credentials'],
            'created_at' => Carbon::now()->subDays(1),
        ]);

        // ACT: Get analytics for 7-day period
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/analytics?period=7d");

        // ASSERT: Response structure and data
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'period',
                    'total_users',
                    'active_tokens',
                    'successful_logins',
                    'failed_logins',
                    'unique_active_users',
                    'login_success_rate',
                ],
            ])
            ->assertJson([
                'data' => [
                    'period' => '7d',
                    'total_users' => 3,
                    'active_tokens' => 2,
                    'successful_logins' => 3,
                    'failed_logins' => 1,
                    'unique_active_users' => 3, // All 3 users had login attempts
                ],
            ]);

        // ASSERT: Success rate calculated correctly
        $data = $response->json('data');
        $expectedSuccessRate = (3 / (3 + 1)) * 100; // 75%
        $this->assertEquals(75.0, $data['login_success_rate']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_api_usage_stats_for_different_periods(): void
    {
        // ARRANGE: Create a dedicated application for this test to ensure test isolation
        $testPassportClient = Client::create([
            'name' => 'Period Test App',
            'secret' => hash('sha256', 'period-test-secret'),
            'redirect' => 'https://period.example.com/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $testApplication = $this->createOAuthApplication([
            'name' => 'Period Test Application',
            'organization_id' => $this->organization->id,
            'client_id' => (string) Str::uuid(),
            'client_secret' => 'period-test-secret',
            'passport_client_id' => $testPassportClient->id,
        ]);

        // Create authentication logs spanning different periods
        $user = $this->createApiUser(['organization_id' => $this->organization->id]);
        $testApplication->users()->attach($user->id, ['granted_at' => now()]);

        // Last 24 hours - Use DB::table to bypass Eloquent timestamps
        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'application_id' => $testApplication->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subHours(2),
            'updated_at' => Carbon::now()->subHours(2),
        ]);

        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'application_id' => $testApplication->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subHours(5),
            'updated_at' => Carbon::now()->subHours(5),
        ]);

        // Last 7 days (but not 24h)
        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'application_id' => $testApplication->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(3),
            'updated_at' => Carbon::now()->subDays(3),
        ]);

        // Last 30 days (but not 7d)
        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'application_id' => $testApplication->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(15),
            'updated_at' => Carbon::now()->subDays(15),
        ]);

        // Last 90 days (but not 30d)
        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'application_id' => $testApplication->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(60),
            'updated_at' => Carbon::now()->subDays(60),
        ]);

        // Outside 90 days (should not be counted)
        \DB::table('authentication_logs')->insert([
            'user_id' => $user->id,
            'application_id' => $testApplication->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(100),
            'updated_at' => Carbon::now()->subDays(100),
        ]);

        // ACT & ASSERT: Test 24h period
        $response24h = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$testApplication->id}/analytics?period=24h");

        $response24h->assertOk()
            ->assertJsonPath('data.period', '24h')
            ->assertJsonPath('data.successful_logins', 2);

        // ACT & ASSERT: Test 7d period
        $response7d = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$testApplication->id}/analytics?period=7d");

        $response7d->assertOk()
            ->assertJsonPath('data.period', '7d')
            ->assertJsonPath('data.successful_logins', 3); // 24h + 7d events

        // ACT & ASSERT: Test 30d period
        $response30d = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$testApplication->id}/analytics?period=30d");

        $response30d->assertOk()
            ->assertJsonPath('data.period', '30d')
            ->assertJsonPath('data.successful_logins', 4); // 24h + 7d + 30d events

        // ACT & ASSERT: Test 90d period
        $response90d = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$testApplication->id}/analytics?period=90d");

        $response90d->assertOk()
            ->assertJsonPath('data.period', '90d')
            ->assertJsonPath('data.successful_logins', 5); // All within 90 days

        // ACT & ASSERT: Test default period (7d)
        $responseDefault = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$testApplication->id}/analytics");

        $responseDefault->assertOk()
            ->assertJsonPath('data.period', '7d')
            ->assertJsonPath('data.successful_logins', 3);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_user_count_and_active_user_metrics(): void
    {
        // ARRANGE: Create multiple users with different activity levels
        $activeUser1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $activeUser2 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $inactiveUser = $this->createApiUser(['organization_id' => $this->organization->id]);

        // Grant all users access
        $this->application->users()->attach($activeUser1->id, ['granted_at' => now()]);
        $this->application->users()->attach($activeUser2->id, ['granted_at' => now()]);
        $this->application->users()->attach($inactiveUser->id, ['granted_at' => now()]);

        // Create active tokens for active users
        Token::create([
            'id' => Str::random(80),
            'user_id' => $activeUser1->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Active User 1 Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHours(1),
        ]);

        Token::create([
            'id' => Str::random(80),
            'user_id' => $activeUser2->id,
            'client_id' => $this->passportClient->id,
            'name' => 'Active User 2 Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => Carbon::now()->addHours(1),
        ]);

        // Create authentication logs for active users in the last 7 days
        AuthenticationLog::create([
            'user_id' => $activeUser1->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(1),
        ]);

        AuthenticationLog::create([
            'user_id' => $activeUser2->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.101',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(2),
        ]);

        // Multiple logins from same user (should count as 1 unique user)
        AuthenticationLog::create([
            'user_id' => $activeUser1->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'created_at' => Carbon::now()->subDays(3),
        ]);

        // Inactive user had no recent logins

        // ACT: Get analytics
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/analytics?period=7d");

        // ASSERT: User metrics
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'total_users' => 3, // All granted users
                    'active_tokens' => 2, // Only non-expired tokens
                    'unique_active_users' => 2, // activeUser1 and activeUser2 (inactiveUser never logged in)
                    'successful_logins' => 3, // Total login events
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_error_rate_analytics_and_failure_patterns(): void
    {
        // ARRANGE: Create mix of successful and failed authentication attempts
        $user1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user2 = $this->createApiUser(['organization_id' => $this->organization->id]);

        // Successful logins - use rand(1, 6) to avoid boundary issues with 7-day period queries
        for ($i = 0; $i < 7; $i++) {
            AuthenticationLog::create([
                'user_id' => $user1->id,
                'organization_id' => $this->organization->id,
                'application_id' => $this->application->id,
                'event' => 'login_success',
                'ip_address' => '192.168.1.100',
                'user_agent' => 'Mozilla/5.0',
                'created_at' => Carbon::now()->subDays(rand(1, 6)),
            ]);
        }

        // Failed logins (various reasons)
        AuthenticationLog::create([
            'user_id' => $user2->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_failed',
            'ip_address' => '192.168.1.101',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['reason' => 'invalid_credentials'],
            'created_at' => Carbon::now()->subDays(1),
        ]);

        AuthenticationLog::create([
            'user_id' => $user2->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_failed',
            'ip_address' => '192.168.1.101',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['reason' => 'account_locked'],
            'created_at' => Carbon::now()->subDays(2),
        ]);

        AuthenticationLog::create([
            'user_id' => $user1->id,
            'organization_id' => $this->organization->id,
            'application_id' => $this->application->id,
            'event' => 'login_failed',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0',
            'metadata' => ['reason' => 'mfa_required'],
            'created_at' => Carbon::now()->subDays(3),
        ]);

        // ACT: Get analytics
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/analytics?period=7d");

        // ASSERT: Error metrics
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'successful_logins' => 7,
                    'failed_logins' => 3,
                ],
            ]);

        $data = $response->json('data');

        // ASSERT: Success rate calculated correctly
        $expectedSuccessRate = (7 / (7 + 3)) * 100; // 70%
        $this->assertEquals(70.0, $data['login_success_rate']);

        // ACT: Test edge case - no failed logins
        AuthenticationLog::where('event', 'login_failed')->delete();

        $noFailuresResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/analytics?period=7d");

        // ASSERT: 100% success rate when no failures
        $noFailuresResponse->assertOk()
            ->assertJson([
                'data' => [
                    'successful_logins' => 7,
                    'failed_logins' => 0,
                    'login_success_rate' => 100.0,
                ],
            ]);

        // ACT: Test edge case - no logins at all
        AuthenticationLog::where('application_id', $this->application->id)->delete();

        $noLoginsResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$this->application->id}/analytics?period=7d");

        // ASSERT: 0% success rate when no logins (avoid division by zero)
        $noLoginsResponse->assertOk()
            ->assertJson([
                'data' => [
                    'successful_logins' => 0,
                    'failed_logins' => 0,
                    'login_success_rate' => 0.0,
                ],
            ]);
    }
}
