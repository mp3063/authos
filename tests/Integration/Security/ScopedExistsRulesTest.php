<?php

namespace Tests\Integration\Security;

use App\Models\CustomRole;
use App\Models\Organization;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Role;
use Tests\Integration\IntegrationTestCase;

class ScopedExistsRulesTest extends IntegrationTestCase
{
    private Organization $other;

    protected function setUp(): void
    {
        parent::setUp();

        $this->other = $this->createOrganization();
    }

    private function role(string $name, ?int $organizationId): Role
    {
        return Role::create(['name' => $name, 'guard_name' => 'api', 'organization_id' => $organizationId]);
    }

    #[Test]
    public function it_rejects_a_foreign_role_filter_on_the_user_list_like_a_nonexistent_one(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->createOrganization()->id]);
        $this->role('Foreign Filter Role', $this->other->id);
        $this->role('Own Filter Role', $owner->organization_id);
        $this->actingAsApiUserWithToken($owner);

        $this->getJson('/api/v1/users?role=Foreign Filter Role')->assertJsonValidationErrors('role');
        $this->getJson('/api/v1/users?role=Nonexistent Role')->assertJsonValidationErrors('role');
        $this->getJson('/api/v1/users?role=Own Filter Role')->assertOk();
        $this->getJson('/api/v1/users?role=Organization Owner')->assertOk();
    }

    #[Test]
    public function it_rejects_a_foreign_role_in_the_export_filter_like_a_nonexistent_one(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->createOrganization()->id]);
        $this->role('Foreign Export Role', $this->other->id);
        $this->role('Own Export Role', $owner->organization_id);
        $this->actingAsApiUserWithToken($owner, ['users.manage']);

        $this->postJson('/api/v1/bulk/users/export', ['format' => 'csv', 'roles' => ['Foreign Export Role']])
            ->assertJsonValidationErrors('roles.0');
        $this->postJson('/api/v1/bulk/users/export', ['format' => 'csv', 'roles' => ['Nonexistent Role']])
            ->assertJsonValidationErrors('roles.0');
        $this->postJson('/api/v1/bulk/users/export', ['format' => 'csv', 'roles' => ['Own Export Role']])
            ->assertJsonMissingValidationErrors('roles.0');
    }

    #[Test]
    public function it_rejects_a_foreign_custom_role_in_bulk_assign_like_a_nonexistent_one(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->createOrganization()->id]);
        $foreign = CustomRole::factory()->create(['organization_id' => $this->other->id]);
        $own = CustomRole::factory()->create(['organization_id' => $owner->organization_id]);
        $member = $this->createApiUser(['organization_id' => $owner->organization_id]);
        $this->actingAsApiUserWithToken($owner);
        $url = "/api/v1/organizations/{$owner->organization_id}/bulk/assign-roles";

        $this->postJson($url, ['user_ids' => [$member->id], 'custom_roles' => [$foreign->id]])
            ->assertJsonValidationErrors('custom_roles.0');
        $this->postJson($url, ['user_ids' => [$member->id], 'custom_roles' => [999999]])
            ->assertJsonValidationErrors('custom_roles.0');
        $this->postJson($url, ['user_ids' => [$member->id], 'custom_roles' => [$own->id]])
            ->assertJsonMissingValidationErrors('custom_roles.0');
    }

    #[Test]
    public function it_lets_a_super_admin_without_an_organization_name_roles_of_the_target_organization(): void
    {
        $admin = $this->createApiSuperAdmin(['organization_id' => null]);
        $this->role('Target Org Role', $this->other->id);
        $custom = CustomRole::factory()->create(['organization_id' => $this->other->id]);
        $member = $this->createApiUser(['organization_id' => $this->other->id]);
        $this->actingAsApiUserWithToken($admin, ['*']);

        $this->getJson('/api/v1/users?role=Target Org Role&organization_id='.$this->other->id)->assertOk();
        $this->getJson('/api/v1/users?role=Target Org Role')->assertOk();
        $this->postJson('/api/v1/bulk/users/export', [
            'format' => 'csv',
            'organization_id' => $this->other->id,
            'roles' => ['Target Org Role'],
        ])->assertJsonMissingValidationErrors('roles.0');
        $this->postJson("/api/v1/organizations/{$this->other->id}/bulk/assign-roles", [
            'user_ids' => [$member->id],
            'custom_roles' => [$custom->id],
        ])->assertJsonMissingValidationErrors('custom_roles.0');
    }
}
