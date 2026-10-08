<?php

namespace Tests\Integration\Users;

use App\Models\CustomRole;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class UserUpdateAuthorizationTest extends IntegrationTestCase
{
    #[Test]
    public function an_organization_admin_cannot_set_another_users_password_with_422(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id, 'password' => Hash::make('Original-Pass-1')]);

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$member->id}", ['password' => 'Attacker-Pass-123!x']);

        $response->assertUnprocessable();
        $this->assertTrue(Hash::check('Original-Pass-1', $member->fresh()->password));
    }

    #[Test]
    public function an_organization_admin_cannot_move_a_user_to_another_organization_with_422(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);
        $otherOrganization = $this->createOrganization();

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$member->id}", ['organization_id' => $otherOrganization->id]);

        $response->assertUnprocessable();
        $this->assertSame($admin->organization_id, $member->fresh()->organization_id);
    }

    #[Test]
    public function an_organization_admin_cannot_update_a_user_with_permissions_they_lack_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $owner = $this->createUser(['organization_id' => $admin->organization_id], 'Organization Owner', 'api');
        $originalEmail = $owner->email;

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$owner->id}", ['email' => 'attacker@example.com']);

        $response->assertForbidden();
        $this->assertSame($originalEmail, $owner->fresh()->email);
    }

    #[Test]
    public function an_organization_admin_can_rename_a_member(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $member = $this->createApiUser(['organization_id' => $admin->organization_id]);

        $response = $this->actingAsApiUserWithToken($admin)
            ->putJson("/api/v1/users/{$member->id}", ['name' => 'Renamed Member']);

        $response->assertOk();
        $this->assertSame('Renamed Member', $member->fresh()->name);
    }

    #[Test]
    public function an_organization_admin_cannot_update_an_owner_when_no_team_id_is_ambient_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $owner = $this->createUser(['organization_id' => $admin->organization_id], 'Organization Owner', 'api');
        $originalEmail = $owner->email;
        $token = $this->generateAccessToken($admin);
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $response = $this->withToken($token)
            ->putJson("/api/v1/users/{$owner->id}", ['email' => 'attacker@example.com']);

        $response->assertForbidden();
        $this->assertSame($originalEmail, $owner->fresh()->email);
    }

    #[Test]
    public function an_organization_admin_with_users_delete_cannot_delete_an_owner_when_no_team_id_is_ambient_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        CustomRole::factory()->forOrganization($admin->organization)
            ->create(['permissions' => ['users.delete']])
            ->assignToUser($admin);
        $owner = $this->createUser(['organization_id' => $admin->organization_id], 'Organization Owner', 'api');
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $response = $this->actingAsApiUserWithToken($admin->fresh())
            ->deleteJson("/api/v1/users/{$owner->id}");

        $response->assertForbidden();
        $this->assertNotNull($owner->fresh());
    }

    #[Test]
    public function an_organization_owner_cannot_update_a_super_admin_of_their_organization_with_403(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $superAdmin = $this->createUser(['organization_id' => $owner->organization_id], 'Super Admin', 'api');
        $originalEmail = $superAdmin->email;
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        $response = $this->actingAsApiUserWithToken($owner->fresh())
            ->putJson("/api/v1/users/{$superAdmin->id}", ['email' => 'attacker@example.com']);

        $response->assertForbidden();
        $this->assertSame($originalEmail, $superAdmin->fresh()->email);
    }
}
