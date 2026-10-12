<?php

namespace Tests\Feature\Filament;

use App\Models\CustomRole;
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
}
