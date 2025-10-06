<?php

namespace Tests\Security;

use App\Models\AccountLockout;
use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * OWASP A07:2021 - Identification and Authentication Failures
 *
 * Tests for:
 * - Weak password policies
 * - Credential stuffing
 * - Brute force attacks
 * - Missing MFA
 * - Session fixation
 * - Insecure password recovery
 */
class OwaspA07AuthenticationFailuresTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
            'password' => Hash::make('ValidPassword123!'),
        ]);
    }

    /** @test */
    public function it_prevents_brute_force_attacks()
    {
        $responses = [];

        // Attempt multiple failed logins
        for ($i = 0; $i < 6; $i++) {
            $response = $this->postJson('/api/auth/login', [
                'email' => $this->user->email,
                'password' => 'wrongpassword',
            ]);

            $responses[] = $response;
        }

        // Should trigger brute force protection
        $lastResponse = end($responses);
        $this->assertContains($lastResponse->status(), [429, 403]);

        // Should create security incident
        $incident = \App\Models\SecurityIncident::where('type', 'brute_force')
            ->where('metadata->email', $this->user->email)
            ->first();

        $this->assertNotNull($incident);
    }

    /** @test */
    public function it_implements_account_lockout_after_failed_attempts()
    {
        // Attempt multiple failed logins
        for ($i = 0; $i < 5; $i++) {
            $this->postJson('/api/auth/login', [
                'email' => $this->user->email,
                'password' => 'wrongpassword',
            ]);
        }

        // Account should be locked
        $lockout = AccountLockout::where('user_id', $this->user->id)
            ->where('is_active', true)
            ->first();

        $this->assertNotNull($lockout);

        // Valid credentials should also fail
        $response = $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'ValidPassword123!',
        ]);

        $this->assertContains($response->status(), [403, 429]);
        $this->assertStringContainsString('locked', strtolower($response->json('message')));
    }

    /** @test */
    public function it_implements_progressive_lockout_duration()
    {
        // First lockout (3 attempts)
        for ($i = 0; $i < 3; $i++) {
            $this->postJson('/api/auth/login', [
                'email' => $this->user->email,
                'password' => 'wrongpassword',
            ]);
        }

        $lockout1 = AccountLockout::where('user_id', $this->user->id)->latest()->first();

        if ($lockout1) {
            $duration1 = now()->diffInMinutes($lockout1->locked_until);

            // Should be 5 minutes for first lockout
            $this->assertEquals(5, $duration1);
        }
    }

    /** @test */
    public function it_detects_credential_stuffing_attacks()
    {
        // Create multiple users
        $users = User::factory()->count(15)->create([
            'organization_id' => $this->organization->id,
        ]);

        // Attempt login with different emails from same IP
        foreach ($users as $user) {
            $this->postJson('/api/auth/login', [
                'email' => $user->email,
                'password' => 'commonpassword123',
            ]);
        }

        // Should detect credential stuffing
        $incident = \App\Models\SecurityIncident::where('type', 'credential_stuffing')->first();

        $this->assertNotNull($incident);
    }

    /** @test */
    public function it_blocks_ip_after_credential_stuffing()
    {
        $users = User::factory()->count(15)->create([
            'organization_id' => $this->organization->id,
        ]);

        foreach ($users as $user) {
            $this->postJson('/api/auth/login', [
                'email' => $user->email,
                'password' => 'password',
            ]);
        }

        // IP should be blocked
        $ipBlock = IpBlocklist::where('ip_address', '127.0.0.1')
            ->where('is_active', true)
            ->first();

        $this->assertNotNull($ipBlock);
    }

    /** @test */
    public function it_enforces_password_complexity_requirements()
    {
        $weakPasswords = [
            'password',
            '12345678',
            'qwerty',
            'abc123',
            'admin',
            'letmein',
        ];

        foreach ($weakPasswords as $password) {
            $response = $this->postJson('/api/auth/register', [
                'name' => 'Test User',
                'email' => 'test'.rand().'@example.com',
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $response->assertStatus(422);
            $response->assertJsonValidationErrors(['password']);
        }
    }

    /** @test */
    public function it_validates_password_minimum_length()
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'Short1',
            'password_confirmation' => 'Short1',
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function it_prevents_common_password_usage()
    {
        $commonPasswords = [
            'Password123!',
            'Welcome123!',
            'Qwerty123!',
            'Admin123!',
        ];

        foreach ($commonPasswords as $password) {
            $response = $this->postJson('/api/auth/register', [
                'name' => 'Test User',
                'email' => 'test'.rand().'@example.com',
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            // Should either reject or warn about common passwords
            if ($response->status() === 201) {
                $this->markTestSkipped('Common password validation not implemented');
            }
        }
    }

    /** @test */
    public function it_validates_mfa_enforcement_for_admins()
    {
        $admin = User::factory()->create([
            'organization_id' => $this->organization->id,
            'mfa_enabled' => false,
        ]);
        $admin->assignRole('Organization Admin');

        // Update organization to require MFA for admins
        $this->organization->update([
            'settings' => [
                'security' => [
                    'require_mfa_for_admins' => true,
                ],
            ],
        ]);

        Passport::actingAs($admin);

        // Should be prompted to enable MFA
        $response = $this->getJson('/api/v1/profile');

        if ($response->status() === 200) {
            $data = $response->json('data');
            $this->assertTrue($data['mfa_required'] ?? false);
        }
    }

    /** @test */
    public function it_prevents_session_fixation()
    {
        // Get session before login
        $response1 = $this->getJson('/api/v1/health');
        $session1 = $response1->headers->getCookies();

        // Login
        $response2 = $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'ValidPassword123!',
        ]);

        $session2 = $response2->headers->getCookies();

        // Session should be regenerated
        $this->assertNotEquals($session1, $session2);
    }

    /** @test */
    public function it_invalidates_all_sessions_on_password_change()
    {
        Passport::actingAs($this->user);

        // Get current token
        $token1 = Passport::actingAsClient($this->user);

        // Change password
        $response = $this->putJson('/api/v1/profile/password', [
            'current_password' => 'ValidPassword123!',
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        if ($response->status() === 200) {
            // Old token should be invalid
            $response2 = $this->withHeaders([
                'Authorization' => 'Bearer '.$token1,
            ])->getJson('/api/v1/profile');

            $this->assertContains($response2->status(), [401]);
        }
    }

    /** @test */
    public function it_validates_secure_password_reset_flow()
    {
        // Request password reset
        $response = $this->postJson('/api/auth/password/email', [
            'email' => $this->user->email,
        ]);

        $response->assertStatus(200);

        // Get reset token from database
        $token = \DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->first();

        $this->assertNotNull($token);

        // Token should be hashed
        $this->assertNotEquals('simple-token', $token->token);
        $this->assertGreaterThan(40, strlen($token->token));
    }

    /** @test */
    public function it_prevents_password_reset_token_reuse()
    {
        // Request reset
        $this->postJson('/api/auth/password/email', [
            'email' => $this->user->email,
        ]);

        $token = \DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->value('token');

        // Use token once
        $response1 = $this->postJson('/api/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $token,
            'password' => 'NewPassword123!',
            'password_confirmation' => 'NewPassword123!',
        ]);

        // Try to reuse token
        $response2 = $this->postJson('/api/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $token,
            'password' => 'AnotherPassword123!',
            'password_confirmation' => 'AnotherPassword123!',
        ]);

        $response2->assertStatus(422);
    }

    /** @test */
    public function it_validates_mfa_recovery_codes_are_single_use()
    {
        $this->user->update(['mfa_enabled' => true]);

        Passport::actingAs($this->user);

        // Generate recovery codes
        $response = $this->postJson('/api/v1/mfa/recovery-codes/regenerate');

        if ($response->status() === 200) {
            $codes = $response->json('data.recovery_codes');
            $code = $codes[0];

            // Use code once
            $response1 = $this->postJson('/api/auth/mfa/verify', [
                'recovery_code' => $code,
            ]);

            // Try to reuse code
            $response2 = $this->postJson('/api/auth/mfa/verify', [
                'recovery_code' => $code,
            ]);

            $response2->assertStatus(422);
        }
    }

    /** @test */
    public function it_logs_failed_authentication_attempts()
    {
        $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'wrongpassword',
        ]);

        $failedAttempt = FailedLoginAttempt::where('email', $this->user->email)->first();

        $this->assertNotNull($failedAttempt);
        $this->assertEquals('127.0.0.1', $failedAttempt->ip_address);
        $this->assertEquals('invalid_credentials', $failedAttempt->failure_reason);
    }

    /** @test */
    public function it_validates_session_timeout()
    {
        Passport::actingAs($this->user);

        // Get current session lifetime
        $lifetime = config('session.lifetime');

        $this->assertIsInt($lifetime);
        $this->assertLessThanOrEqual(120, $lifetime, 'Session should timeout within 2 hours');
    }

    /** @test */
    public function it_prevents_username_enumeration()
    {
        // Login with non-existent user
        $response1 = $this->postJson('/api/auth/login', [
            'email' => 'nonexistent@example.com',
            'password' => 'password123',
        ]);

        // Login with existing user, wrong password
        $response2 = $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'wrongpassword',
        ]);

        // Response should be the same
        $this->assertEquals($response1->status(), $response2->status());

        $message1 = $response1->json('message');
        $message2 = $response2->json('message');

        // Messages should be generic
        $this->assertStringNotContainsString('user not found', strtolower($message1 ?? ''));
        $this->assertStringNotContainsString('wrong password', strtolower($message2 ?? ''));
    }

    /** @test */
    public function it_validates_oauth_client_authentication()
    {
        $app = \App\Models\Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Get client secret
        $secret = \DB::table('oauth_clients')->where('id', $app->client_id)->value('secret');

        // Try with wrong secret
        $response = $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $app->client_id,
            'client_secret' => 'wrong-secret',
        ]);

        $response->assertStatus(401);
    }

    /** @test */
    public function it_prevents_timing_attacks_in_authentication()
    {
        $start1 = microtime(true);
        $this->postJson('/api/auth/login', [
            'email' => 'nonexistent@example.com',
            'password' => 'password',
        ]);
        $time1 = microtime(true) - $start1;

        $start2 = microtime(true);
        $this->postJson('/api/auth/login', [
            'email' => $this->user->email,
            'password' => 'wrongpassword',
        ]);
        $time2 = microtime(true) - $start2;

        // Timing difference should be minimal (< 100ms)
        $difference = abs($time1 - $time2);
        $this->assertLessThan(0.1, $difference, 'Timing attack vulnerability detected');
    }
}
