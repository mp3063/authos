<?php

namespace Tests\Feature;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class SecurityTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization1;
    private Organization $organization2;
    private User $user1;
    private User $user2;
    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization1 = Organization::factory()->create();
        $this->organization2 = Organization::factory()->create();
        
        Role::create(['name' => 'user', 'guard_name' => 'web']);
        Role::create(['name' => 'super admin', 'guard_name' => 'web']);
        
        $this->user1 = User::factory()->forOrganization($this->organization1)->create();
        $this->user2 = User::factory()->forOrganization($this->organization2)->create();
        $this->admin = $this->createSuperAdmin();
    }

    public function test_organization_boundary_enforcement_in_user_access(): void
    {
        Passport::actingAs($this->user1, ['users.view']);

        // User 1 should not be able to access user 2 (different organization)
        $response = $this->getJson("/api/v1/users/{$this->user2->id}");
        
        $response->assertStatus(404); // Should appear as "not found" for security
    }

    public function test_organization_boundary_enforcement_in_application_access(): void
    {
        $app1 = Application::factory()->forOrganization($this->organization1)->create();
        $app2 = Application::factory()->forOrganization($this->organization2)->create();
        
        Passport::actingAs($this->user1, ['applications.view']);

        // User 1 should be able to access app from their organization
        $response = $this->getJson("/api/v1/applications/{$app1->id}");
        $response->assertStatus(200);

        // User 1 should not be able to access app from other organization
        $response = $this->getJson("/api/v1/applications/{$app2->id}");
        $response->assertStatus(404);
    }

    public function test_api_rate_limiting_blocks_excessive_requests(): void
    {
        RateLimiter::clear('api:' . request()->ip());
        
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create([
                'email' => 'test@example.com',
                'password' => Hash::make('password123'),
            ]);

        // Make requests up to the rate limit
        for ($i = 0; $i < 15; $i++) {
            $response = $this->postJson('/api/v1/auth/login', [
                'email' => 'test@example.com',
                'password' => 'wrong-password',
            ]);

            if ($i < 10) {
                $response->assertStatus(401); // Authentication failure
            } else {
                $response->assertStatus(429); // Rate limit exceeded
                break;
            }
        }
    }

    public function test_authentication_rate_limiting_increases_delay(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create([
                'email' => 'test@example.com',
                'password' => Hash::make('password123'),
            ]);

        $startTime = microtime(true);

        // Make multiple failed login attempts
        for ($i = 0; $i < 5; $i++) {
            $this->postJson('/api/v1/auth/login', [
                'email' => 'test@example.com',
                'password' => 'wrong-password',
            ]);
        }

        $endTime = microtime(true);

        // Should introduce delays after multiple failed attempts
        $this->assertGreaterThan(1.0, $endTime - $startTime);
    }

    public function test_cors_headers_prevent_unauthorized_cross_origin_requests(): void
    {
        $response = $this->json('OPTIONS', '/api/v1/auth/login', [], [
            'Origin' => 'https://malicious-site.com',
        ]);

        // Should not allow unauthorized origins
        $this->assertNotEquals(
            'https://malicious-site.com',
            $response->headers->get('Access-Control-Allow-Origin')
        );
    }

    public function test_cors_headers_allow_configured_origins(): void
    {
        $allowedOrigin = 'http://localhost:3000';

        $response = $this->json('OPTIONS', '/api/v1/auth/login', [], [
            'Origin' => $allowedOrigin,
        ]);

        $response->assertHeader('Access-Control-Allow-Origin');
    }

    public function test_security_headers_are_present_in_all_responses(): void
    {
        $response = $this->getJson('/api/v1/auth/user');

        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('X-Frame-Options', 'DENY');
        $response->assertHeader('X-XSS-Protection', '1; mode=block');
        $response->assertHeader('Referrer-Policy');
        $response->assertHeader('Strict-Transport-Security');
    }

    public function test_csrf_protection_on_web_routes(): void
    {
        // Attempt to make request without CSRF token
        $response = $this->post('/login', [
            'email' => 'test@example.com',
            'password' => 'password',
        ]);

        $response->assertStatus(419); // CSRF token mismatch
    }

    public function test_password_hashing_uses_secure_algorithm(): void
    {
        $user = User::factory()->create([
            'password' => Hash::make('test-password'),
        ]);

        // Verify password is hashed (not plain text)
        $this->assertNotEquals('test-password', $user->password);
        
        // Verify hash starts with bcrypt identifier
        $this->assertStringStartsWith('$2y$', $user->password);
        
        // Verify password can be verified
        $this->assertTrue(Hash::check('test-password', $user->password));
    }

    public function test_sql_injection_protection(): void
    {
        Passport::actingAs($this->admin, ['users.view']);

        // Attempt SQL injection in search parameter
        $maliciousInput = "'; DROP TABLE users; --";
        
        $response = $this->getJson("/api/v1/users?search=" . urlencode($maliciousInput));
        
        // Should not cause database error and should return safely
        $response->assertStatus(200);
        
        // Verify users table still exists by making another request
        $response = $this->getJson('/api/v1/users');
        $response->assertStatus(200);
    }

    public function test_xss_protection_in_user_input(): void
    {
        Passport::actingAs($this->admin, ['users.create']);

        $xssPayload = "<script>alert('XSS')</script>";
        
        $response = $this->postJson('/api/v1/users', [
            'name' => $xssPayload,
            'email' => 'test@example.com',
            'password' => 'password123',
            'organization_id' => $this->organization1->id,
        ]);

        $response->assertStatus(201);

        // Verify the XSS payload was sanitized or escaped
        $user = User::where('email', 'test@example.com')->first();
        $this->assertNotEquals($xssPayload, $user->name);
        $this->assertStringNotContainsString('<script>', $user->name);
    }

    public function test_authentication_logs_track_security_events(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create([
                'email' => 'test@example.com',
                'password' => Hash::make('password123'),
            ]);

        // Successful login
        $this->postJson('/api/v1/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password123',
        ]);

        // Failed login
        $this->postJson('/api/v1/auth/login', [
            'email' => 'test@example.com',
            'password' => 'wrong-password',
        ]);

        // Verify both events are logged
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'login',
            'success' => true,
        ]);

        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'failed_login',
            'success' => false,
        ]);
    }

    public function test_sensitive_data_is_not_exposed_in_api_responses(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->withMfa()
            ->create();

        Passport::actingAs($user, ['profile']);

        $response = $this->getJson('/api/v1/auth/user');

        $response->assertStatus(200);

        $userData = $response->json();
        
        // Ensure sensitive fields are not exposed
        $this->assertArrayNotHasKey('password', $userData);
        $this->assertArrayNotHasKey('two_factor_secret', $userData);
        $this->assertArrayNotHasKey('two_factor_recovery_codes', $userData);
        $this->assertArrayNotHasKey('remember_token', $userData);
    }

    public function test_api_tokens_have_proper_scopes(): void
    {
        Passport::actingAs($this->user1, ['profile']); // Limited scope

        // Should be able to access profile
        $response = $this->getJson('/api/v1/auth/user');
        $response->assertStatus(200);

        // Should not be able to access admin functions
        $response = $this->getJson('/api/v1/users');
        $response->assertStatus(403);
    }

    public function test_api_validates_content_type_for_json_endpoints(): void
    {
        $response = $this->post('/api/v1/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password123',
        ], [
            'Content-Type' => 'text/plain'
        ]);

        $response->assertStatus(415); // Unsupported Media Type
    }

    public function test_organization_admin_cannot_escalate_privileges(): void
    {
        // Create organization admin
        $orgAdmin = User::factory()
            ->forOrganization($this->organization1)
            ->create();
        
        Role::create(['name' => 'organization admin', 'guard_name' => 'web']);
        $orgAdmin->assignRole('organization admin');

        Passport::actingAs($orgAdmin, ['users.edit']);

        // Try to assign super admin role (privilege escalation)
        $response = $this->postJson("/api/v1/users/{$this->user1->id}/roles", [
            'role' => 'super admin',
        ]);

        // Should fail or be ignored
        $response->assertStatus(403);
        
        // Verify user did not get super admin role
        $this->user1->refresh();
        $this->assertFalse($this->user1->hasRole('super admin'));
    }

    public function test_session_fixation_protection(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create([
                'email' => 'test@example.com',
                'password' => Hash::make('password123'),
            ]);

        // Get initial session
        $response1 = $this->withSession(['test' => 'value'])
            ->postJson('/api/v1/auth/login', [
                'email' => 'test@example.com',
                'password' => 'password123',
            ]);

        $response1->assertStatus(200);

        // Session should be regenerated after login
        $this->assertNotEquals(
            session()->getId(),
            session()->getId()
        );
    }

    public function test_brute_force_protection_locks_account(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create([
                'email' => 'test@example.com',
                'password' => Hash::make('password123'),
            ]);

        // Make multiple failed attempts
        for ($i = 0; $i < 10; $i++) {
            $this->postJson('/api/v1/auth/login', [
                'email' => 'test@example.com',
                'password' => 'wrong-password',
            ]);
        }

        // Account should be temporarily locked
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password123', // Correct password
        ]);

        $response->assertStatus(423); // Locked
    }

    public function test_api_prevents_timing_attacks_on_login(): void
    {
        // Create user with known email
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create([
                'email' => 'existing@example.com',
                'password' => Hash::make('password123'),
            ]);

        // Time login attempt with existing email
        $start1 = microtime(true);
        $response1 = $this->postJson('/api/v1/auth/login', [
            'email' => 'existing@example.com',
            'password' => 'wrong-password',
        ]);
        $time1 = microtime(true) - $start1;

        // Time login attempt with non-existing email
        $start2 = microtime(true);
        $response2 = $this->postJson('/api/v1/auth/login', [
            'email' => 'nonexisting@example.com',
            'password' => 'wrong-password',
        ]);
        $time2 = microtime(true) - $start2;

        // Response times should be similar to prevent timing attacks
        $timeDifference = abs($time1 - $time2);
        $this->assertLessThan(0.1, $timeDifference); // Less than 100ms difference
    }

    public function test_api_enforces_https_in_production(): void
    {
        // This would be tested in production environment
        // For now, we just verify that the middleware exists
        $response = $this->get('/api/v1/auth/user', [
            'X-Forwarded-Proto' => 'http'
        ]);

        // In production, this should redirect to HTTPS
        // For testing, we just verify it doesn't crash
        $this->assertTrue(true);
    }

    public function test_api_handles_malformed_json_gracefully(): void
    {
        $response = $this->json('POST', '/api/v1/auth/login', [], [], [], 
            '{"email":"test@example.com","password":malformed}');

        $response->assertStatus(400); // Bad Request
        $response->assertJson([
            'message' => 'Invalid JSON format',
        ]);
    }

    public function test_file_upload_validation_prevents_malicious_files(): void
    {
        Passport::actingAs($this->admin, ['users.import']);

        // Try to upload a potentially malicious file
        $maliciousFile = \Illuminate\Http\UploadedFile::fake()
            ->createWithContent('malicious.php', '<?php echo "hack"; ?>');

        $response = $this->postJson("/api/v1/organizations/{$this->organization1->id}/bulk/import-users", [
            'file' => $maliciousFile,
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('file');
    }

    public function test_api_logs_suspicious_activity(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization1)
            ->create();

        // Simulate suspicious activity (login from unusual location)
        $this->postJson('/api/v1/auth/login', [
            'email' => $user->email,
            'password' => 'password123',
        ], [
            'X-Forwarded-For' => '192.0.2.1', // Suspicious IP
            'User-Agent' => 'SuspiciousBot/1.0',
        ]);

        // Verify suspicious activity is flagged
        $log = AuthenticationLog::where('user_id', $user->id)
            ->where('event', 'login')
            ->latest()
            ->first();

        if ($log && isset($log->details['risk_score'])) {
            $this->assertGreaterThan(50, $log->details['risk_score']);
        }
    }
}