<?php

namespace Tests\Integration\Security;

use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class PermissionContextTest extends IntegrationTestCase
{
    #[Test]
    public function it_sets_the_permission_team_after_bearer_authentication(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $token = $this->createAccessToken($owner, ['*']);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $this->withToken($token)->getJson('/api/v1/auth/user')->assertOk();

        $this->assertSame($owner->organization_id, app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    #[Test]
    public function it_sets_the_permission_team_after_panel_authentication(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $this->actingAs($owner)->get('/admin')->assertOk();

        $this->assertSame($owner->organization_id, app(PermissionRegistrar::class)->getPermissionsTeamId());
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
