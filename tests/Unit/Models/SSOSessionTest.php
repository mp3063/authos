<?php

namespace Tests\Unit\Models;

use App\Models\Application;
use App\Models\SSOSession;
use App\Models\User;
use Carbon\Carbon;
use Tests\TestCase;

class SSOSessionTest extends TestCase
{
    private User $user;

    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        $this->user = $this->createUser();
        $this->application = Application::factory()->create();
    }

    public function test_sso_session_belongs_to_user(): void
    {
        $session = SSOSession::factory()
            ->forUser($this->user)
            ->create();

        $this->assertInstanceOf(User::class, $session->user);
        $this->assertEquals($this->user->id, $session->user->id);
    }

    public function test_sso_session_belongs_to_application(): void
    {
        $session = SSOSession::factory()
            ->forApplication($this->application)
            ->create();

        $this->assertInstanceOf(Application::class, $session->application);
        $this->assertEquals($this->application->id, $session->application->id);
    }

    public function test_active_scope_filters_active_sessions(): void
    {
        // Create active session
        $activeSession = SSOSession::factory()
            ->recentlyActive()
            ->create(['logged_out_at' => null]);

        // Create expired session
        $expiredSession = SSOSession::factory()
            ->expired()
            ->create();

        // Create logged out session
        $loggedOutSession = SSOSession::factory()
            ->create(['logged_out_at' => Carbon::now()]);

        $activeSessions = SSOSession::active()->get();

        $this->assertCount(1, $activeSessions);
        $this->assertEquals($activeSession->id, $activeSessions->first()->id);
    }

    public function test_expired_scope_filters_expired_sessions(): void
    {
        // Create expired session
        $expiredSession = SSOSession::factory()
            ->expired()
            ->create();

        // Create active session
        $activeSession = SSOSession::factory()
            ->recentlyActive()
            ->create();

        $expiredSessions = SSOSession::expired()->get();

        $this->assertCount(1, $expiredSessions);
        $this->assertEquals($expiredSession->id, $expiredSessions->first()->id);
    }

    public function test_for_user_scope_filters_by_user(): void
    {
        $otherUser = $this->createUser();

        // Create session for our user
        $ourSession = SSOSession::factory()
            ->forUser($this->user)
            ->create();

        // Create session for other user
        $otherSession = SSOSession::factory()
            ->forUser($otherUser)
            ->create();

        $userSessions = SSOSession::forUser($this->user->id)->get();

        $this->assertCount(1, $userSessions);
        $this->assertEquals($ourSession->id, $userSessions->first()->id);
    }

    public function test_for_application_scope_filters_by_application(): void
    {
        $otherApplication = Application::factory()->create();

        // Create session for our application
        $ourSession = SSOSession::factory()
            ->forApplication($this->application)
            ->create();

        // Create session for other application
        $otherSession = SSOSession::factory()
            ->forApplication($otherApplication)
            ->create();

        $appSessions = SSOSession::forApplication($this->application->id)->get();

        $this->assertCount(1, $appSessions);
        $this->assertEquals($ourSession->id, $appSessions->first()->id);
    }

    public function test_is_active_returns_true_for_active_session(): void
    {
        $session = SSOSession::factory()
            ->recentlyActive()
            ->create([
                'expires_at' => Carbon::now()->addHours(2),
                'logged_out_at' => null,
            ]);

        $this->assertTrue($session->isActive());
    }

    public function test_is_active_returns_false_for_expired_session(): void
    {
        $session = SSOSession::factory()
            ->create([
                'expires_at' => Carbon::now()->subHour(),
                'logged_out_at' => null,
            ]);

        $this->assertFalse($session->isActive());
    }

    public function test_is_active_returns_false_for_logged_out_session(): void
    {
        $session = SSOSession::factory()
            ->create([
                'expires_at' => Carbon::now()->addHours(2),
                'logged_out_at' => Carbon::now()->subMinutes(30),
            ]);

        $this->assertFalse($session->isActive());
    }

    public function test_is_expired_returns_true_for_expired_session(): void
    {
        $session = SSOSession::factory()
            ->create(['expires_at' => Carbon::now()->subHour()]);

        $this->assertTrue($session->isExpired());
    }

    public function test_is_expired_returns_false_for_active_session(): void
    {
        $session = SSOSession::factory()
            ->create(['expires_at' => Carbon::now()->addHours(2)]);

        $this->assertFalse($session->isExpired());
    }

    public function test_extend_session_updates_expiry_time(): void
    {
        $session = SSOSession::factory()
            ->create(['expires_at' => Carbon::now()->addHour()]);

        $originalExpiry = $session->expires_at;

        $session->extendSession(3600); // 1 hour in seconds

        $this->assertTrue($session->expires_at->gt($originalExpiry));
        $this->assertEquals(
            $originalExpiry->addSeconds(3600)->timestamp,
            $session->expires_at->timestamp
        );
    }

    public function test_update_last_activity_sets_current_time(): void
    {
        $session = SSOSession::factory()
            ->create(['last_activity_at' => Carbon::now()->subHours(2)]);

        $beforeUpdate = Carbon::now()->subSecond();
        $session->updateLastActivity();
        $afterUpdate = Carbon::now()->addSecond();

        $this->assertTrue($session->last_activity_at->between($beforeUpdate, $afterUpdate));
    }

    public function test_logout_marks_session_as_logged_out(): void
    {
        $session = SSOSession::factory()
            ->create(['logged_out_at' => null]);

        $loggedOutBy = $this->user->id;
        $session->logout($loggedOutBy);

        $this->assertNotNull($session->logged_out_at);
        $this->assertEquals($loggedOutBy, $session->logged_out_by);
    }

    public function test_generate_new_session_token_creates_unique_token(): void
    {
        $session = SSOSession::factory()->create();
        $originalToken = $session->session_token;

        $session->generateNewSessionToken();

        $this->assertNotEquals($originalToken, $session->session_token);
        $this->assertEquals(64, strlen($session->session_token)); // Standard token length
    }

    public function test_generate_new_refresh_token_creates_unique_token(): void
    {
        $session = SSOSession::factory()->create();
        $originalToken = $session->refresh_token;

        $session->generateNewRefreshToken();

        $this->assertNotEquals($originalToken, $session->refresh_token);
        $this->assertEquals(64, strlen($session->refresh_token)); // Standard token length
    }

    public function test_get_device_info_extracts_device_information(): void
    {
        $userAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15';

        $session = SSOSession::factory()
            ->create(['user_agent' => $userAgent]);

        $deviceInfo = $session->getDeviceInfo();

        $this->assertArrayHasKey('device', $deviceInfo);
        $this->assertArrayHasKey('browser', $deviceInfo);
        $this->assertArrayHasKey('platform', $deviceInfo);
    }

    public function test_get_location_info_returns_location_from_metadata(): void
    {
        $metadata = [
            'location' => [
                'country' => 'United States',
                'city' => 'New York',
                'region' => 'NY',
            ],
        ];

        $session = SSOSession::factory()
            ->create(['metadata' => $metadata]);

        $location = $session->getLocationInfo();

        $this->assertEquals('United States', $location['country']);
        $this->assertEquals('New York', $location['city']);
        $this->assertEquals('NY', $location['region']);
    }

    public function test_is_suspicious_identifies_suspicious_sessions(): void
    {
        // Create session with high risk factors
        $suspiciousSession = SSOSession::factory()
            ->create([
                'metadata' => [
                    'risk_score' => 85,
                    'risk_factors' => ['unusual_location', 'new_device', 'tor_network'],
                ],
            ]);

        // Create normal session
        $normalSession = SSOSession::factory()
            ->create([
                'metadata' => [
                    'risk_score' => 20,
                    'risk_factors' => [],
                ],
            ]);

        $this->assertTrue($suspiciousSession->isSuspicious());
        $this->assertFalse($normalSession->isSuspicious());
    }

    public function test_minutes_since_last_activity_calculates_correctly(): void
    {
        $session = SSOSession::factory()
            ->create(['last_activity_at' => Carbon::now()->subMinutes(30)]);

        $minutes = $session->minutesSinceLastActivity();

        $this->assertEquals(30, $minutes);
    }

    public function test_hours_until_expiry_calculates_correctly(): void
    {
        $session = SSOSession::factory()
            ->create(['expires_at' => Carbon::now()->addHours(3)]);

        $hours = $session->hoursUntilExpiry();

        $this->assertEquals(3, $hours);
    }

    public function test_metadata_is_cast_to_array(): void
    {
        $metadata = [
            'login_method' => 'oauth',
            'device_type' => 'mobile',
            'risk_score' => 25,
        ];

        $session = SSOSession::factory()
            ->create(['metadata' => $metadata]);

        $this->assertIsArray($session->metadata);
        $this->assertEquals($metadata, $session->metadata);
    }

    public function test_session_has_correct_fillable_attributes(): void
    {
        $fillable = [
            'user_id', 'application_id', 'session_token', 'refresh_token',
            'external_session_id', 'ip_address', 'user_agent', 'expires_at',
            'last_activity_at', 'logged_out_at', 'logged_out_by', 'metadata',
        ];

        $session = new SSOSession;

        $this->assertEquals($fillable, $session->getFillable());
    }

    public function test_session_casts_dates_correctly(): void
    {
        $session = SSOSession::factory()->create();

        $this->assertInstanceOf(\Carbon\Carbon::class, $session->expires_at);
        $this->assertInstanceOf(\Carbon\Carbon::class, $session->last_activity_at);
        $this->assertInstanceOf(\Carbon\Carbon::class, $session->created_at);
        $this->assertInstanceOf(\Carbon\Carbon::class, $session->updated_at);

        if ($session->logged_out_at) {
            $this->assertInstanceOf(\Carbon\Carbon::class, $session->logged_out_at);
        }
    }

    public function test_find_by_session_token_returns_correct_session(): void
    {
        $session = SSOSession::factory()->create();
        $foundSession = SSOSession::findBySessionToken($session->session_token);

        $this->assertInstanceOf(SSOSession::class, $foundSession);
        $this->assertEquals($session->id, $foundSession->id);
    }

    public function test_find_by_session_token_returns_null_for_invalid_token(): void
    {
        $foundSession = SSOSession::findBySessionToken('invalid-token');

        $this->assertNull($foundSession);
    }

    public function test_cleanup_expired_removes_expired_sessions(): void
    {
        // Create expired sessions
        SSOSession::factory()->count(3)->expired()->create();

        // Create active session
        $activeSession = SSOSession::factory()->recentlyActive()->create();

        $deletedCount = SSOSession::cleanupExpired();

        $this->assertEquals(3, $deletedCount);
        $this->assertDatabaseHasModel($activeSession);
        $this->assertDatabaseCount('sso_sessions', 1);
    }
}
