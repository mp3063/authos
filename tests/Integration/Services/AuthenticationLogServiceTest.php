<?php

namespace Tests\Integration\Services;

use App\Models\AuthenticationLog;
use App\Models\User;
use App\Services\AuthenticationLogService;
use Illuminate\Http\Request;
use Tests\Integration\IntegrationTestCase;

class AuthenticationLogServiceTest extends IntegrationTestCase
{
    private AuthenticationLogService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new AuthenticationLogService;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_logs_authentication_event(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/login', 'POST');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');
        $request->headers->set('User-Agent', 'Mozilla/5.0');

        $this->service->logAuthenticationEvent($user, 'login_success', [], $request);

        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'success' => true,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_logs_event_with_metadata(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/login', 'POST');
        $metadata = [
            'method' => 'password',
            'client_id' => 'test-client',
        ];

        $this->service->logAuthenticationEvent($user, 'login_success', $metadata, $request);

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertEquals('password', $log->metadata['method']);
        $this->assertEquals('test-client', $log->metadata['client_id']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_current_request_when_not_provided(): void
    {
        $user = User::factory()->create();

        // Set up global request
        $request = Request::create('/test', 'GET');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        app()->instance('request', $request);

        $this->service->logAuthenticationEvent($user, 'test_event');

        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'test_event',
            'ip_address' => '10.0.0.1',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('successEventProvider')]
    public function it_determines_success_from_event_name(string $event, bool $expectedSuccess): void
    {
        $user = User::factory()->create();
        $request = Request::create('/test', 'POST');

        $this->service->logAuthenticationEvent($user, $event, [], $request);

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertEquals($expectedSuccess, $log->success);
    }

    public static function successEventProvider(): array
    {
        return [
            'login success' => ['login_success', true],
            'logout' => ['logout', true],
            'token refresh' => ['token_refresh', true],
            'login failed' => ['login_failed', false],
            'failed MFA' => ['failed_mfa', false],
            'oauth token failed' => ['oauth_token_failed', false],
            'social login failed' => ['social_login_failed', false],
            'account locked' => ['account_locked', false],
        ];
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_allows_explicit_success_override(): void
    {
        $user = User::factory()->create();
        $request = Request::create('/test', 'POST');

        // Override default behavior for 'login_success'
        $this->service->logAuthenticationEvent($user, 'login_success', [], $request, false);

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertFalse($log->success);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_fallback_ip_address(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/test', 'POST');
        // Don't set IP address

        $this->service->logAuthenticationEvent($user, 'test_event', [], $request);

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertEquals('127.0.0.1', $log->ip_address);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_fallback_user_agent(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/test', 'POST');
        // Explicitly remove User-Agent header
        $request->headers->remove('User-Agent');

        $this->service->logAuthenticationEvent($user, 'test_event', [], $request);

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertEquals('Unknown', $log->user_agent);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_logs_authentication_event_with_details(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/oauth/token', 'POST');
        $request->server->set('REMOTE_ADDR', '192.168.1.100');
        $request->headers->set('User-Agent', 'OAuth Client/1.0');

        $this->service->logAuthenticationEventWithDetails(
            $user,
            'oauth_token_generated',
            $request,
            'test-client-123',
            true
        );

        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'oauth_token_generated',
            'ip_address' => '192.168.1.100',
            'user_agent' => 'OAuth Client/1.0',
            'success' => true,
        ]);

        $log = AuthenticationLog::where('user_id', $user->id)->first();
        $this->assertEquals('test-client-123', $log->metadata['client_id']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_logs_failed_authentication_with_details(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/oauth/token', 'POST');

        $this->service->logAuthenticationEventWithDetails(
            $user,
            'oauth_failed',
            $request,
            'invalid-client',
            false
        );

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertFalse($log->success);
        $this->assertEquals('oauth_failed', $log->event);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_basic_user_info(): void
    {
        $user = User::factory()->create([
            'id' => 123,
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);

        $userInfo = $this->service->getUserInfo($user, []);

        $this->assertEquals('123', $userInfo['sub']);
        $this->assertArrayNotHasKey('name', $userInfo);
        $this->assertArrayNotHasKey('email', $userInfo);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_user_info_with_profile_scope(): void
    {
        $user = User::factory()->create([
            'id' => 123,
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);

        $userInfo = $this->service->getUserInfo($user, ['profile']);

        $this->assertEquals('123', $userInfo['sub']);
        $this->assertEquals('John Doe', $userInfo['name']);
        $this->assertEquals('John Doe', $userInfo['preferred_username']);
        $this->assertArrayHasKey('updated_at', $userInfo);
        $this->assertArrayNotHasKey('email', $userInfo);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_user_info_with_email_scope(): void
    {
        $user = User::factory()->create([
            'id' => 123,
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'email_verified_at' => now(),
        ]);

        $userInfo = $this->service->getUserInfo($user, ['email']);

        $this->assertEquals('123', $userInfo['sub']);
        $this->assertEquals('john@example.com', $userInfo['email']);
        $this->assertTrue($userInfo['email_verified']);
        $this->assertArrayNotHasKey('name', $userInfo);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_user_info_with_multiple_scopes(): void
    {
        $user = User::factory()->create([
            'id' => 123,
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'email_verified_at' => now(),
        ]);

        $userInfo = $this->service->getUserInfo($user, ['profile', 'email']);

        $this->assertEquals('123', $userInfo['sub']);
        $this->assertEquals('John Doe', $userInfo['name']);
        $this->assertEquals('john@example.com', $userInfo['email']);
        $this->assertTrue($userInfo['email_verified']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_indicates_unverified_email(): void
    {
        $user = User::factory()->create([
            'email' => 'unverified@example.com',
            'email_verified_at' => null,
        ]);

        $userInfo = $this->service->getUserInfo($user, ['email']);

        $this->assertEquals('unverified@example.com', $userInfo['email']);
        $this->assertFalse($userInfo['email_verified']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_includes_metadata_in_detailed_log(): void
    {
        $user = User::factory()->create();

        $request = Request::create('/test', 'POST');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');
        $request->headers->set('User-Agent', 'Test Agent');

        $this->service->logAuthenticationEventWithDetails(
            $user,
            'test_event',
            $request,
            'client-id-123'
        );

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertIsArray($log->metadata);
        $this->assertEquals('client-id-123', $log->metadata['client_id']);
        $this->assertEquals('Test Agent', $log->metadata['user_agent']);
        $this->assertEquals('192.168.1.1', $log->metadata['ip_address']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_null_client_id_in_detailed_log(): void
    {
        $user = User::factory()->create();
        $request = Request::create('/test', 'POST');

        $this->service->logAuthenticationEventWithDetails(
            $user,
            'test_event',
            $request,
            null
        );

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        $this->assertNull($log->metadata['client_id']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_stores_timestamp_correctly(): void
    {
        $user = User::factory()->create();
        $request = Request::create('/test', 'POST');

        $beforeLog = now();
        $this->service->logAuthenticationEvent($user, 'test_event', [], $request);
        $afterLog = now();

        $log = AuthenticationLog::where('user_id', $user->id)->first();

        // Compare timestamps to avoid Carbon object comparison issues
        $this->assertGreaterThanOrEqual($beforeLog->timestamp, $log->created_at->timestamp);
        $this->assertLessThanOrEqual($afterLog->timestamp, $log->created_at->timestamp);
    }
}
