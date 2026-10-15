<?php

namespace Tests\Feature\Filament;

use App\Models\CustomRole;
use App\Services\SocialAuthService;
use Laravel\Socialite\Two\User as SocialiteTwoUser;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class PanelAccessTest extends IntegrationTestCase
{
    #[Test]
    public function it_lets_an_organization_owner_open_the_panel_on_a_fresh_request(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $owner->unsetRelation('roles')->unsetRelation('permissions');

        $this->actingAs($owner)->get('/admin')->assertOk();
    }

    #[Test]
    public function it_denies_a_regular_user_the_panel_with_403(): void
    {
        $user = $this->createUser([], 'User', 'web');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $user->unsetRelation('roles')->unsetRelation('permissions');

        $this->actingAs($user)->get('/admin')->assertForbidden();
    }

    #[Test]
    public function it_lets_a_custom_role_with_admin_access_open_the_panel(): void
    {
        $user = $this->createUser([], 'User', 'web');
        CustomRole::factory()->forOrganization($user->organization)
            ->create(['permissions' => ['admin.access']])
            ->assignToUser($user);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $user->unsetRelation('roles')->unsetRelation('permissions');

        $this->actingAs($user)->get('/admin')->assertOk();
    }

    #[Test]
    public function it_admits_panel_users_through_social_login_by_permission(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $member = $this->createUser([], 'User', 'web');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $socialAuth = Mockery::mock(SocialAuthService::class);
        $socialAuth->shouldReceive('isProviderSupported')->andReturnTrue();
        $socialAuth->shouldReceive('isProviderEnabled')->andReturnTrue();
        $socialUser = new SocialiteTwoUser;
        $socialAuth->shouldReceive('findPanelUser')->andReturn([$owner->fresh(), $socialUser], [$member->fresh(), $socialUser]);
        $socialAuth->shouldReceive('connectProvider')->once();
        $socialAuth->shouldReceive('logAuthentication');
        $this->app->instance(SocialAuthService::class, $socialAuth);

        $this->get('/auth/social/google/callback')->assertRedirect('/admin');
        $this->assertAuthenticatedAs($owner);

        auth()->logout();
        $this->get('/auth/social/google/callback')->assertRedirect('/admin/login?error=insufficient_privileges');
        $this->assertGuest();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function rolesWithoutPanelAccess(): array
    {
        return [
            'Organization Member' => ['Organization Member'],
            'Application Manager' => ['Application Manager'],
            'User Manager' => ['User Manager'],
            'Auditor' => ['Auditor'],
        ];
    }

    #[Test]
    #[DataProvider('rolesWithoutPanelAccess')]
    public function it_denies_roles_without_admin_access_the_panel(string $role): void
    {
        $user = $this->createUser([], $role, 'web');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $user->unsetRelation('roles')->unsetRelation('permissions');

        $this->actingAs($user)->get('/admin')->assertForbidden();
    }
}
