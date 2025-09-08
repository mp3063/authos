<?php

namespace Tests\Feature;

use App\Models\User;
use App\Models\Organization;
use App\Services\SocialAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Laravel\Passport\Passport;
use Mockery;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class SocialAuthControllerTest extends TestCase
{
    use RefreshDatabase;

    private $mockSocialAuthService;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up test configuration
        Config::set('services.google', [
            'client_id' => 'test_client_id',
            'client_secret' => 'test_client_secret',
            'redirect' => 'http://localhost/callback'
        ]);
        
        $this->mockSocialAuthService = Mockery::mock(SocialAuthService::class);
        $this->app->instance(SocialAuthService::class, $this->mockSocialAuthService);
    }

    public function test_providers_endpoint_returns_available_providers()
    {
        $mockProviders = [
            'google' => [
                'name' => 'Google',
                'enabled' => true,
                'icon' => 'fab fa-google',
                'color' => '#db4437',
            ]
        ];
        
        $this->mockSocialAuthService
            ->shouldReceive('getAvailableProviders')
            ->andReturn($mockProviders);
            
        $response = $this->getJson('/api/v1/auth/social/providers');
        
        $response->assertOk()
            ->assertJsonStructure([
                'success',
                'data' => [
                    'providers',
                    'count'
                ]
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'providers' => $mockProviders,
                    'count' => 1
                ]
            ]);
    }

    public function test_redirect_endpoint_returns_redirect_url_for_valid_provider()
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with('google')
            ->andReturn('https://accounts.google.com/oauth/authorize?...');
            
        $response = $this->getJson('/api/v1/auth/social/google');
        
        $response->assertOk()
            ->assertJsonStructure([
                'success',
                'data' => [
                    'redirect_url',
                    'provider'
                ]
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'provider' => 'google'
                ]
            ]);
    }

    public function test_redirect_endpoint_rejects_unsupported_provider()
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('invalid')
            ->andReturn(false);
            
        $response = $this->getJson('/api/v1/auth/social/invalid');
        
        $response->assertBadRequest()
            ->assertJson([
                'success' => false,
                'message' => 'Unsupported social provider'
            ]);
    }

    public function test_redirect_endpoint_rejects_disabled_provider()
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('github')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('github')
            ->andReturn(false);
            
        $response = $this->getJson('/api/v1/auth/social/github');
        
        $response->assertBadRequest()
            ->assertJson([
                'success' => false,
                'message' => 'Social provider is not configured'
            ]);
    }

    public function test_callback_endpoint_authenticates_user_successfully()
    {
        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '12345',
        ]);
        
        $mockResult = [
            'user' => $user,
            'access_token' => 'jwt_token_here',
            'refresh_token' => 'refresh_token_here',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ];
        
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', null)
            ->andReturn($mockResult);
            
        $response = $this->getJson('/api/v1/auth/social/google/callback');
        
        $response->assertOk()
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'access_token',
                    'refresh_token',
                    'expires_in',
                    'token_type',
                    'user' => [
                        'id',
                        'name',
                        'email',
                        'provider',
                        'provider_display_name',
                        'is_social_user',
                        'has_password',
                        'mfa_enabled',
                        'is_active',
                    ]
                ]
            ])
            ->assertJson([
                'success' => true,
                'message' => 'Authentication successful'
            ]);
    }

    public function test_callback_endpoint_with_organization_parameter()
    {
        $organization = Organization::factory()->create(['slug' => 'test-org']);
        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '12345',
            'organization_id' => $organization->id,
        ]);
        
        $mockResult = [
            'user' => $user,
            'access_token' => 'jwt_token_here',
            'refresh_token' => 'refresh_token_here',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ];
        
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', 'test-org')
            ->andReturn($mockResult);
            
        $response = $this->getJson('/api/v1/auth/social/google/callback?organization=test-org');
        
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'data' => [
                    'user' => [
                        'organization' => [
                            'id' => $organization->id,
                            'slug' => 'test-org',
                        ]
                    ]
                ]
            ]);
    }

    public function test_callback_endpoint_handles_authentication_failure()
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google', null)
            ->andThrow(new \Exception('Authentication failed'));
            
        $response = $this->getJson('/api/v1/auth/social/google/callback');
        
        $response->assertBadRequest()
            ->assertJson([
                'success' => false,
                'message' => 'Authentication failed',
                'error' => 'Authentication failed'
            ]);
    }

    public function test_unlink_endpoint_removes_social_provider_data()
    {
        $user = User::factory()->create([
            'password' => bcrypt('password'),
            'provider' => 'google',
            'provider_id' => '12345',
            'provider_token' => 'token',
            'provider_refresh_token' => 'refresh_token',
        ]);
        
        Passport::actingAs($user, ['*']);
        
        $response = $this->deleteJson('/api/v1/auth/social/unlink');
        
        $response->assertOk()
            ->assertJson([
                'success' => true,
                'message' => 'Social account unlinked successfully'
            ]);
            
        $user->refresh();
        $this->assertNull($user->provider);
        $this->assertNull($user->provider_id);
        $this->assertNull($user->provider_token);
        $this->assertNull($user->provider_refresh_token);
    }

    public function test_unlink_endpoint_fails_for_user_without_password()
    {
        $user = User::factory()->create([
            'password' => null,
            'provider' => 'google',
            'provider_id' => '12345',
        ]);
        
        Passport::actingAs($user, ['*']);
        
        $response = $this->deleteJson('/api/v1/auth/social/unlink');
        
        $response->assertBadRequest()
            ->assertJson([
                'success' => false,
                'message' => 'Cannot unlink social account without setting a password first'
            ]);
    }

    public function test_unlink_endpoint_requires_authentication()
    {
        $response = $this->deleteJson('/api/v1/auth/social/unlink');
        
        $response->assertUnauthorized();
    }

    public function test_web_login_redirects_to_provider()
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('getRedirectUrl')
            ->with('google')
            ->andReturn('https://accounts.google.com/oauth/authorize?...');
            
        $response = $this->get('/auth/social/google');
        
        $response->assertRedirect('https://accounts.google.com/oauth/authorize?...');
    }

    public function test_web_login_handles_unsupported_provider()
    {
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('invalid')
            ->andReturn(false);
            
        $response = $this->get('/auth/social/invalid');
        
        $response->assertRedirect('/admin/login?error=unsupported_provider');
    }

    public function test_web_callback_logs_in_admin_user()
    {
        $adminRole = Role::create(['name' => 'Super Admin', 'guard_name' => 'web']);
        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '12345',
        ]);
        $user->assignRole($adminRole);
        
        $mockResult = [
            'user' => $user->load('roles'),
            'access_token' => 'jwt_token_here',
            'refresh_token' => 'refresh_token_here',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ];
        
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google')
            ->andReturn($mockResult);
            
        $response = $this->get('/auth/social/google/callback');
        
        $response->assertRedirect('/admin');
        $this->assertAuthenticatedAs($user);
    }

    public function test_web_callback_rejects_non_admin_user()
    {
        $userRole = Role::create(['name' => 'user', 'guard_name' => 'web']);
        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '12345',
        ]);
        $user->assignRole($userRole);
        
        $mockResult = [
            'user' => $user->load('roles'),
            'access_token' => 'jwt_token_here',
            'refresh_token' => 'refresh_token_here',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ];
        
        $this->mockSocialAuthService
            ->shouldReceive('isProviderSupported')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('isProviderEnabled')
            ->with('google')
            ->andReturn(true);
            
        $this->mockSocialAuthService
            ->shouldReceive('handleCallback')
            ->with('google')
            ->andReturn($mockResult);
            
        $response = $this->get('/auth/social/google/callback');
        
        $response->assertRedirect('/admin/login?error=insufficient_privileges');
        $this->assertGuest();
    }
}