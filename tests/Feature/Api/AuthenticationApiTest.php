<?php

namespace Tests\Feature\Api;

use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class AuthenticationApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization = Organization::factory()->create();
        
        // Create required roles
        Role::create(['name' => 'user', 'guard_name' => 'web']);
        Role::create(['name' => 'super admin', 'guard_name' => 'web']);
    }

    public function test_register_creates_new_user_and_returns_token(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
            'organization_slug' => $this->organization->slug,
            'profile' => [
                'bio' => 'Software developer',
                'location' => 'New York',
            ],
            'terms_accepted' => true,
        ];

        $response = $this->postJson('/api/v1/auth/register', $userData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'user' => [
                    'id',
                    'name',
                    'email',
                    'organization_id',
                    'profile',
                    'is_active',
                ],
                'token' => [
                    'access_token',
                    'token_type',
                    'expires_at',
                ],
                'scopes',
            ]);

        $this->assertDatabaseHas('users', [
            'email' => 'john@example.com',
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        // Verify user has default role
        $user = User::where('email', 'john@example.com')->first();
        $this->assertTrue($user->hasRole('user'));

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'registration',
            'success' => true,
        ]);
    }

    public function test_register_fails_with_invalid_organization_slug(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
            'organization_slug' => 'invalid-slug',
            'terms_accepted' => true,
        ];

        $response = $this->postJson('/api/v1/auth/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('organization_slug');
    }

    public function test_register_fails_without_terms_acceptance(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
            'organization_slug' => $this->organization->slug,
            'terms_accepted' => false,
        ];

        $response = $this->postJson('/api/v1/auth/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('terms_accepted');
    }

    public function test_login_with_valid_credentials_returns_token(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'email' => 'user@example.com',
                'password' => Hash::make('password123'),
            ]);

        $loginData = [
            'email' => 'user@example.com',
            'password' => 'password123',
            'scopes' => ['openid', 'profile', 'email'],
        ];

        $response = $this->postJson('/api/v1/auth/login', $loginData);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'user' => [
                    'id',
                    'name',
                    'email',
                    'organization_id',
                ],
                'token' => [
                    'access_token',
                    'token_type',
                    'expires_at',
                    'scopes',
                ],
            ]);

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'login',
            'success' => true,
        ]);
    }

    public function test_login_with_invalid_credentials_fails(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'email' => 'user@example.com',
                'password' => Hash::make('password123'),
            ]);

        $loginData = [
            'email' => 'user@example.com',
            'password' => 'wrong-password',
        ];

        $response = $this->postJson('/api/v1/auth/login', $loginData);

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Invalid credentials',
            ]);

        // Verify failed login log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'failed_login',
            'success' => false,
        ]);
    }

    public function test_login_with_inactive_user_fails(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->inactive()
            ->create([
                'email' => 'user@example.com',
                'password' => Hash::make('password123'),
            ]);

        $loginData = [
            'email' => 'user@example.com',
            'password' => 'password123',
        ];

        $response = $this->postJson('/api/v1/auth/login', $loginData);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Account is inactive',
            ]);
    }

    public function test_login_with_mfa_required_returns_mfa_challenge(): void
    {
        $organization = Organization::factory()->requiresMfa()->create();
        $user = User::factory()
            ->forOrganization($organization)
            ->withMfa()
            ->create([
                'email' => 'user@example.com',
                'password' => Hash::make('password123'),
            ]);

        $loginData = [
            'email' => 'user@example.com',
            'password' => 'password123',
        ];

        $response = $this->postJson('/api/v1/auth/login', $loginData);

        $response->assertStatus(202)
            ->assertJsonStructure([
                'message',
                'mfa_required',
                'challenge_token',
                'available_methods',
            ])
            ->assertJson([
                'mfa_required' => true,
            ]);
    }

    public function test_get_authenticated_user_returns_user_info(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($user, ['openid', 'profile']);

        $response = $this->getJson('/api/v1/auth/user');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'id',
                'name',
                'email',
                'organization' => [
                    'id',
                    'name',
                    'slug',
                ],
                'roles',
                'permissions',
                'profile',
                'mfa_enabled',
            ])
            ->assertJson([
                'id' => $user->id,
                'email' => $user->email,
            ]);
    }

    public function test_get_authenticated_user_requires_authentication(): void
    {
        $response = $this->getJson('/api/v1/auth/user');

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Unauthenticated.',
            ]);
    }

    public function test_refresh_token_generates_new_token(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $token = $user->createToken('TestToken', ['*']);
        $refreshToken = $token->token->refresh_token;

        $response = $this->postJson('/api/v1/auth/refresh', [
            'refresh_token' => $refreshToken,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'access_token',
                'token_type',
                'expires_at',
                'scopes',
            ]);
    }

    public function test_refresh_token_fails_with_invalid_token(): void
    {
        $response = $this->postJson('/api/v1/auth/refresh', [
            'refresh_token' => 'invalid-token',
        ]);

        $response->assertStatus(401)
            ->assertJson([
                'message' => 'Invalid refresh token',
            ]);
    }

    public function test_revoke_token_invalidates_access_token(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $token = $user->createToken('TestToken', ['*']);

        Passport::actingAs($user, ['*']);

        $response = $this->postJson('/api/v1/auth/revoke', [
            'token_id' => $token->token->id,
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Token revoked successfully',
            ]);

        // Verify token is revoked
        $this->assertTrue($token->token->fresh()->revoked);
    }

    public function test_logout_revokes_current_token_and_logs_event(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($user, ['*']);

        $response = $this->postJson('/api/v1/auth/logout');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Successfully logged out',
            ]);

        // Verify logout log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'logout',
            'success' => true,
        ]);
    }

    public function test_logout_requires_authentication(): void
    {
        $response = $this->postJson('/api/v1/auth/logout');

        $response->assertStatus(401);
    }

    public function test_api_rate_limiting_blocks_excessive_requests(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'email' => 'user@example.com',
                'password' => Hash::make('password123'),
            ]);

        // Make multiple login attempts
        for ($i = 0; $i < 15; $i++) {
            $response = $this->postJson('/api/v1/auth/login', [
                'email' => 'user@example.com',
                'password' => 'wrong-password',
            ]);

            if ($i < 10) {
                $response->assertStatus(401);
            } else {
                $response->assertStatus(429); // Too Many Requests
                break;
            }
        }
    }

    public function test_registration_validates_password_strength(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => '123', // Weak password
            'password_confirmation' => '123',
            'organization_slug' => $this->organization->slug,
            'terms_accepted' => true,
        ];

        $response = $this->postJson('/api/v1/auth/register', $userData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('password');
    }

    public function test_login_tracks_ip_and_user_agent(): void
    {
        $user = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'email' => 'user@example.com',
                'password' => Hash::make('password123'),
            ]);

        $response = $this->postJson('/api/v1/auth/login', [
            'email' => 'user@example.com',
            'password' => 'password123',
        ], [
            'X-Forwarded-For' => '192.168.1.100',
            'User-Agent' => 'TestAgent/1.0',
        ]);

        $response->assertStatus(200);

        // Verify tracking data in authentication log
        $log = AuthenticationLog::where('user_id', $user->id)
            ->where('event', 'login')
            ->latest()
            ->first();

        $this->assertEquals('192.168.1.100', $log->ip_address);
        $this->assertEquals('TestAgent/1.0', $log->user_agent);
    }

    public function test_registration_respects_organization_settings(): void
    {
        $restrictedOrg = Organization::factory()
            ->create([
                'settings' => [
                    'allow_registration' => false,
                ]
            ]);

        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
            'organization_slug' => $restrictedOrg->slug,
            'terms_accepted' => true,
        ];

        $response = $this->postJson('/api/v1/auth/register', $userData);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Registration is not allowed for this organization',
            ]);
    }

    public function test_api_returns_consistent_error_format(): void
    {
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => 'invalid-email',
            'password' => '',
        ]);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'message',
                'errors' => [
                    'email',
                    'password',
                ],
            ]);
    }

    public function test_cors_headers_are_present_in_responses(): void
    {
        $response = $this->postJson('/api/v1/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password',
        ], [
            'Origin' => 'http://localhost:3000',
        ]);

        $response->assertHeader('Access-Control-Allow-Origin');
        $response->assertHeader('Access-Control-Allow-Methods');
        $response->assertHeader('Access-Control-Allow-Headers');
    }

    public function test_security_headers_are_present(): void
    {
        $response = $this->getJson('/api/v1/auth/user');

        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $response->assertHeader('X-Frame-Options', 'DENY');
        $response->assertHeader('X-XSS-Protection', '1; mode=block');
    }
}