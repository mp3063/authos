<?php

namespace Tests\Integration\Organizations;

use App\Models\Organization;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Tests\Integration\IntegrationTestCase;

class OrganizationDefaultRolesSetupTest extends IntegrationTestCase
{
    #[Test]
    public function it_gives_a_new_organization_its_default_roles_in_both_guards(): void
    {
        $organization = Organization::factory()->create();

        $roleNames = array_keys($organization->getDefaultRoles());

        foreach (['web', 'api'] as $guard) {
            $this->assertEqualsCanonicalizing(
                $roleNames,
                Role::where('organization_id', $organization->id)->where('guard_name', $guard)->pluck('name')->all(),
            );
        }

        $owner = Role::where('organization_id', $organization->id)->where('guard_name', 'web')->where('name', 'Organization Owner')->first();
        $this->assertEqualsCanonicalizing(
            $organization->getDefaultRoles()['Organization Owner'],
            $owner->permissions->pluck('name')->all(),
        );
    }

    #[Test]
    public function it_binds_default_roles_only_to_the_organizations_own_permissions(): void
    {
        $this->artisan('db:seed', ['--class' => 'RolePermissionSeeder']);
        $first = Organization::factory()->create();
        $second = Organization::factory()->create();

        $boundOrganizationIds = Role::where('organization_id', $second->id)
            ->with('permissions')
            ->get()
            ->flatMap->permissions
            ->pluck('organization_id')
            ->unique()
            ->values()
            ->all();

        $this->assertSame([$second->id], $boundOrganizationIds);

        $first->forceDelete();

        $this->assertTrue(
            Role::where('organization_id', $second->id)->where('guard_name', 'web')->where('name', 'Organization Owner')->first()
                ->permissions()->where('name', 'roles.assign')->exists()
        );
    }

    #[Test]
    public function it_lets_a_member_of_a_new_organization_be_given_a_default_role(): void
    {
        $organization = Organization::factory()->create();
        $user = $this->createUser(['organization_id' => $organization->id], '');

        $user->assignOrganizationRole('Organization Admin');

        $this->assertTrue($user->fresh()->hasOrganizationPermission('webhooks.read'));
    }

    #[Test]
    public function the_backfill_command_sets_up_organizations_created_without_default_roles(): void
    {
        $bare = Organization::withoutEvents(fn () => Organization::factory()->create());
        $complete = Organization::factory()->create();
        $completeRoleIds = Role::where('organization_id', $complete->id)->pluck('id')->sort()->values()->all();

        $this->artisan('organizations:setup-default-roles')
            ->expectsOutput('Set up default roles for 1 organization(s).')
            ->assertSuccessful();

        $this->assertSame(count($bare->getDefaultRoles()) * 2, Role::where('organization_id', $bare->id)->count());
        $this->assertTrue(Permission::where('organization_id', $bare->id)->where('name', 'roles.assign')->exists());
        $this->assertSame($completeRoleIds, Role::where('organization_id', $complete->id)->pluck('id')->sort()->values()->all());

        $this->artisan('organizations:setup-default-roles')
            ->expectsOutput('Set up default roles for 0 organization(s).')
            ->assertSuccessful();
    }
}
