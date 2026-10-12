<?php

namespace Tests\Unit;

use App\Models\Organization;
use App\Models\User;
use App\Services\AuthenticationLogService;
use App\Services\SocialAuthService;
use App\Services\UserRoleService;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class SocialAuthServiceTest extends TestCase
{
    private SocialAuthService $socialAuthService;

    private $mockAuthLogService;

    private $mockSocialiteUser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockAuthLogService = Mockery::mock(AuthenticationLogService::class);
        $this->socialAuthService = new SocialAuthService($this->mockAuthLogService);

        $this->mockSocialiteUser = Mockery::mock(SocialiteUser::class);

        // Create default role
        Role::firstOrCreate(['name' => 'user', 'guard_name' => 'api']);

        // Set up test configuration
        Config::set('services.google', [
            'client_id' => 'test_client_id',
            'client_secret' => 'test_client_secret',
            'redirect' => 'http://localhost/callback',
        ]);
    }

    public function test_get_available_providers_returns_correct_structure()
    {
        $providers = $this->socialAuthService->getAvailableProviders();

        $this->assertIsArray($providers);
        $this->assertArrayHasKey('google', $providers);
        $this->assertArrayHasKey('github', $providers);

        foreach ($providers as $provider) {
            $this->assertArrayHasKey('name', $provider);
            $this->assertArrayHasKey('enabled', $provider);
            $this->assertArrayHasKey('icon', $provider);
            $this->assertArrayHasKey('color', $provider);
        }
    }

    public function test_is_provider_supported_returns_true_for_valid_providers()
    {
        $this->assertTrue($this->socialAuthService->isProviderSupported('google'));
        $this->assertTrue($this->socialAuthService->isProviderSupported('github'));
        $this->assertFalse($this->socialAuthService->isProviderSupported('invalid'));
    }

    public function test_is_provider_enabled_returns_correct_status()
    {
        $this->assertTrue($this->socialAuthService->isProviderEnabled('google'));
        $this->assertFalse($this->socialAuthService->isProviderEnabled('github')); // No config
    }

    public function test_get_redirect_url_returns_valid_url()
    {
        $mockDriver = Mockery::mock();
        $mockDriver->shouldReceive('stateless')->andReturnSelf();
        $mockDriver->shouldReceive('scopes')->with(['openid', 'profile', 'email'])->andReturnSelf();
        $mockDriver->shouldReceive('with')->with(Mockery::type('array'))->andReturnSelf();
        $mockDriver->shouldReceive('redirect')->andReturnSelf();
        $mockDriver->shouldReceive('getTargetUrl')->andReturn('https://accounts.google.com/oauth/authorize?...');

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturn($mockDriver);

        $redirectUrl = $this->socialAuthService->getRedirectUrl('google');

        $this->assertStringStartsWith('https://accounts.google.com', $redirectUrl);
    }

    public function test_handle_callback_creates_new_user()
    {
        $this->setupMockSocialiteUser();
        $this->setupMockSocialite();
        $this->setupMockOAuthService();

        $result = $this->socialAuthService->handleCallback('google');

        $this->assertArrayHasKey('user', $result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('token_type', $result);

        $user = $result['user'];
        $this->assertEquals('John Doe', $user->name);
        $this->assertEquals('john@example.com', $user->email);
        $this->assertEquals('google', $user->provider);
    }

    public function test_handle_callback_updates_existing_social_user()
    {
        $existingUser = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '12345',
            'email' => 'john@example.com',
        ]);

        $this->setupMockSocialiteUser();
        $this->setupMockSocialite();
        $this->setupMockOAuthService();

        $result = $this->socialAuthService->handleCallback('google');

        $user = $result['user'];
        $this->assertEquals($existingUser->id, $user->id);
        $this->assertEquals('John Doe', $user->name); // Updated name
    }

    public function test_handle_callback_links_social_account_to_existing_user()
    {
        $existingUser = User::factory()->create([
            'email' => 'john@example.com',
            'provider' => null,
            'provider_id' => null,
        ]);

        $this->setupMockSocialiteUser();
        $this->setupMockSocialite();
        $this->setupMockOAuthService();

        $result = $this->socialAuthService->handleCallback('google');

        $user = $result['user'];
        $this->assertEquals($existingUser->id, $user->id);
        $this->assertEquals('google', $user->provider);
        $this->assertEquals('12345', $user->provider_id);
    }

    public function test_handle_callback_with_organization_slug()
    {
        $organization = Organization::factory()->create([
            'slug' => 'test-org',
            'settings' => ['allow_registration' => true],
        ]);

        Role::firstOrCreate(['name' => 'user', 'guard_name' => 'api', 'organization_id' => $organization->id]);

        $this->setupMockSocialiteUser();
        $this->setupMockSocialite();
        $this->setupMockOAuthService();

        $result = $this->socialAuthService->handleCallback('google', 'test-org');

        $user = $result['user'];
        $this->assertEquals($organization->id, $user->organization_id);
    }

    public function test_default_role_for_new_social_user_is_tied_to_the_users_organization()
    {
        $organization = Organization::factory()->create([
            'slug' => 'role-org',
            'settings' => ['allow_registration' => true],
        ]);

        $role = Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api', 'organization_id' => $organization->id]);
        $role->givePermissionTo(Permission::firstOrCreate(['name' => 'users.read', 'guard_name' => 'api']));

        $this->setupMockSocialiteUser();
        $this->setupMockSocialite();
        $this->setupMockOAuthService();

        $user = $this->socialAuthService->handleCallback('google', 'role-org')['user'];

        $this->assertSame(
            [$role->id],
            app(UserRoleService::class)->assignedRoleIds($user)->all()
        );
        $this->assertSame(
            $organization->id,
            (int) DB::table('model_has_roles')->where('model_id', $user->id)->value('organization_id')
        );
        $this->assertTrue($user->fresh()->hasOrganizationPermission('users.read'));
    }

    public function test_handle_callback_fails_with_organization_that_disallows_registration()
    {
        Organization::factory()->create([
            'slug' => 'restricted-org',
            'settings' => ['allow_registration' => false],
        ]);

        $this->setupMockSocialiteUser();
        $this->setupMockSocialite();

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Organization does not allow registration');

        $this->socialAuthService->handleCallback('google', 'restricted-org');
    }

    public function test_handle_callback_handles_socialite_exception()
    {
        Socialite::shouldReceive('driver')
            ->with('google')
            ->andThrow(new \Exception('OAuth error'));

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Social authentication failed');

        $this->socialAuthService->handleCallback('google');
    }

    private function setupMockSocialiteUser()
    {
        $this->mockSocialiteUser->shouldReceive('getId')->andReturn('12345');
        $this->mockSocialiteUser->shouldReceive('getName')->andReturn('John Doe');
        $this->mockSocialiteUser->shouldReceive('getEmail')->andReturn('john@example.com');
        $this->mockSocialiteUser->shouldReceive('getAvatar')->andReturn('https://example.com/avatar.jpg');
        $this->mockSocialiteUser->shouldReceive('getNickname')->andReturn('johndoe');
        $this->mockSocialiteUser->shouldReceive('getRaw')->andReturn(['id' => '12345', 'name' => 'John Doe']);
        $this->mockSocialiteUser->token = 'access_token_123';
        $this->mockSocialiteUser->refreshToken = 'refresh_token_123';
    }

    private function setupMockSocialite()
    {
        $mockDriver = Mockery::mock();
        $mockDriver->shouldReceive('stateless')->andReturnSelf();
        $mockDriver->shouldReceive('user')->andReturn($this->mockSocialiteUser);

        Socialite::shouldReceive('driver')
            ->with('google')
            ->andReturn($mockDriver);
    }

    private function setupMockOAuthService()
    {
        $mockTokenObject = (object) [
            'access_token' => 'jwt_token_here',
            'refresh_token' => 'refresh_token_here',
            'expires_in' => 3600,
        ];

        $this->mockAuthLogService->shouldReceive('logAuthenticationEvent')
            ->once() // Called once for token creation, authentication is logged directly
            ->andReturn();
    }
}
