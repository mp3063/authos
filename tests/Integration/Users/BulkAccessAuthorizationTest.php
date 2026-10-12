<?php

namespace Tests\Integration\Users;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Services\UserRoleService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class BulkAccessAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    private function revokeAllRoles(User $caller, array $userIds)
    {
        Passport::actingAs($caller, ['applications.update']);

        return $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/revoke-access", [
            'user_ids' => $userIds,
            'reason' => 'cleanup',
        ]);
    }

    private function roleIds(User $user): array
    {
        return app(UserRoleService::class)->assignedRoleIds($user)->sort()->values()->all();
    }

    #[Test]
    public function an_organization_admin_cannot_revoke_an_owners_roles(): void
    {
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $before = $this->roleIds($owner);

        $response = $this->revokeAllRoles($admin, [$owner->id]);

        $response->assertOk();
        $this->assertSame($before, $this->roleIds($owner));
        $this->assertNotEmpty($before);
    }

    #[Test]
    public function an_owner_can_revoke_a_peers_organization_roles(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $peer = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);

        $this->revokeAllRoles($owner, [$peer->id])->assertOk();

        $this->assertSame([], $this->roleIds($peer));
    }

    #[Test]
    public function an_owner_cannot_revoke_their_own_roles(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $before = $this->roleIds($owner);

        $this->revokeAllRoles($owner, [$owner->id])->assertOk();

        $this->assertSame($before, $this->roleIds($owner));
    }

    #[Test]
    public function a_super_admin_with_an_organization_keeps_the_super_admin_role(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $superAdmin = $this->createUser(['organization_id' => $this->organization->id], 'Super Admin', 'api');
        $before = $this->roleIds($superAdmin);

        $this->revokeAllRoles($owner, [$superAdmin->id])->assertOk();

        $this->assertSame($before, $this->roleIds($superAdmin));
        $this->assertTrue($superAdmin->fresh()->isSuperAdmin());
    }

    #[Test]
    public function roles_of_the_target_in_another_organization_survive(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $peer = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $foreignRole = Role::create([
            'name' => 'Foreign Role',
            'guard_name' => 'api',
            'organization_id' => Organization::factory()->create()->id,
        ]);
        DB::table('model_has_roles')->insert([
            'role_id' => $foreignRole->id,
            'model_type' => $peer->getMorphClass(),
            'model_id' => $peer->id,
            'organization_id' => $foreignRole->organization_id,
        ]);

        $this->revokeAllRoles($owner, [$peer->id])->assertOk();

        $this->assertSame([$foreignRole->id], $this->roleIds($peer));
    }

    #[Test]
    public function a_foreign_user_id_is_neither_listed_nor_touched_when_revoking_application_access(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $foreignUser = User::factory()->create(['organization_id' => Organization::factory()->create()->id]);
        $foreignUser->applications()->attach($application->id, ['granted_at' => now()]);
        Passport::actingAs($owner, ['applications.update']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/revoke-access", [
            'user_ids' => [$foreignUser->id],
            'application_id' => $application->id,
        ]);

        $response->assertOk();
        $this->assertStringNotContainsString($foreignUser->email, $response->getContent());
        $this->assertDatabaseHas('user_applications', [
            'user_id' => $foreignUser->id,
            'application_id' => $application->id,
        ]);
    }

    #[Test]
    public function a_foreign_application_id_is_rejected(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $foreignApplication = Application::factory()->create(['organization_id' => Organization::factory()->create()->id]);
        Passport::actingAs($owner, ['applications.update']);

        $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/revoke-access", [
            'user_ids' => [$owner->id],
            'application_id' => $foreignApplication->id,
        ])->assertUnprocessable();
    }

    #[Test]
    public function a_user_without_an_organization_can_list_their_own_applications(): void
    {
        $user = User::factory()->create(['organization_id' => null]);
        Passport::actingAs($user, ['applications.read']);

        $this->getJson("/api/v1/users/{$user->id}/applications")->assertOk();
    }
}
