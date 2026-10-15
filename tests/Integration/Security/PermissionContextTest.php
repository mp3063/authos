<?php

namespace Tests\Integration\Security;

use App\Http\Middleware\SetPermissionContext;
use Filament\Facades\Filament;
use Filament\Http\Middleware\Authenticate;
use Filament\Support\Facades\FilamentView;
use Filament\View\PanelsRenderHook;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class PermissionContextTest extends IntegrationTestCase
{
    #[Test]
    public function it_sets_the_permission_team_after_bearer_authentication_and_clears_it_afterwards(): void
    {
        Route::middleware(['api', 'auth:api'])->get('/api/v1/__permission-team', fn () => ['team' => app(PermissionRegistrar::class)->getPermissionsTeamId()]);
        $owner = $this->createApiOrganizationOwner();
        $token = $this->createAccessToken($owner, ['*']);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $this->withToken($token)->getJson('/api/v1/__permission-team')->assertOk()->assertJsonPath('team', $owner->organization_id);

        $this->assertNull(app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    #[Test]
    public function the_panel_authenticates_before_it_sets_the_permission_team(): void
    {
        $middleware = Filament::getPanel('admin')->getAuthMiddleware();

        $this->assertContains(SetPermissionContext::class, $middleware);
        $this->assertLessThan(
            array_search(SetPermissionContext::class, $middleware, true),
            array_search(Authenticate::class, $middleware, true)
        );
    }

    #[Test]
    public function it_sets_the_permission_team_on_a_real_panel_request(): void
    {
        $captured = [];
        FilamentView::registerRenderHook(PanelsRenderHook::BODY_START, function () use (&$captured) {
            $captured[] = app(PermissionRegistrar::class)->getPermissionsTeamId();

            return '';
        });
        $admin = $this->createOrganizationAdmin();
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $this->actingAs($admin)->get('/admin')->assertOk();

        $this->assertNotEmpty($captured);
        $this->assertSame([$admin->organization_id], array_values(array_unique($captured)));
    }

    #[Test]
    public function a_super_admin_with_an_organization_keeps_cross_organization_api_access(): void
    {
        $superAdmin = $this->createApiSuperAdmin();
        $otherOrganization = $this->createOrganization();
        $otherUser = $this->createApiUser(['organization_id' => $otherOrganization->id]);
        $token = $this->createAccessToken($superAdmin, ['*']);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $response = $this->withToken($token)->getJson("/api/v1/organizations/{$otherOrganization->id}/users");

        $response->assertOk();
        $this->assertContains($otherUser->id, collect($response->json('data'))->pluck('id')->all());
    }
}
