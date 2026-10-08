<?php

namespace Tests\Unit\Authorization;

use App\Models\CustomRole;
use App\Models\User;
use Database\Seeders\RolePermissionSeeder;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;
use Tests\TestCase;

class OrganizationPermissionResolverTest extends TestCase
{
    #[Test]
    public function it_resolves_a_permission_of_an_org_role_without_a_preset_team_id(): void
    {
        $user = $this->createUser([], 'Organization Admin', 'web');
        $this->clearAmbientTeam($user);

        $this->assertTrue($user->hasOrganizationPermission('users.read'));
        $this->assertTrue($user->can('users.read'));
        $this->assertFalse($user->hasOrganizationPermission('organizations.update'));
    }

    #[Test]
    public function it_resolves_the_same_answer_for_web_and_api_guard_roles(): void
    {
        $webAdmin = $this->createUser([], 'Organization Admin', 'web');
        $apiAdmin = $this->createUser([], 'Organization Admin', 'api');

        foreach ([$webAdmin, $apiAdmin] as $user) {
            $this->clearAmbientTeam($user);

            $this->assertTrue($user->hasOrganizationPermission('users.update'));
            $this->assertTrue($user->can('users.update'));
            $this->assertFalse($user->hasOrganizationPermission('organizations.update'));
            $this->assertFalse($user->can('organizations.update'));
        }
    }

    #[Test]
    public function it_resolves_custom_role_permissions(): void
    {
        $user = $this->createUser([], 'User', 'web');
        $customRole = CustomRole::factory()->forOrganization($user->organization)->create([
            'permissions' => ['webhooks.update'],
        ]);
        $customRole->assignToUser($user);
        $this->clearAmbientTeam($user);

        $this->assertTrue($user->hasOrganizationPermission('webhooks.update'));
        $this->assertTrue($user->can('webhooks.update'));
        $this->assertFalse($user->hasOrganizationPermission('webhooks.delete'));
    }

    #[Test]
    public function it_denies_users_without_an_organization(): void
    {
        $user = $this->createUser([], 'Organization Owner', 'web');
        $user->update(['organization_id' => null]);

        $this->assertFalse($user->hasOrganizationPermission('users.read'));
        $this->assertFalse($user->can('users.read'));
    }

    #[Test]
    public function it_returns_false_for_an_unknown_permission(): void
    {
        $user = $this->createUser([], 'Organization Owner', 'web');
        CustomRole::factory()->forOrganization($user->organization)->create([
            'permissions' => ['reports.view'],
        ])->assignToUser($user);

        $this->assertFalse($user->hasOrganizationPermission('nonexistent.permission'));
        $this->assertFalse($user->hasOrganizationPermission('reports.view'));
    }

    #[Test]
    public function it_restores_the_previous_team_id(): void
    {
        $user = $this->createUser([], 'Organization Admin', 'web');
        $otherOrganizationAdmin = $this->createUser([], 'Organization Admin', 'web');
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId($otherOrganizationAdmin->organization_id);

        $this->assertTrue($user->hasOrganizationPermission('users.read'));
        $this->assertTrue($user->can('users.read'));
        $this->assertSame($otherOrganizationAdmin->organization_id, $registrar->getPermissionsTeamId());
    }

    #[Test]
    public function it_resolves_global_role_permissions_for_a_user_without_an_organization(): void
    {
        $systemAdministrator = $this->createSystemAdministrator();

        $this->assertTrue($systemAdministrator->hasOrganizationPermission('admin.access'));
        $this->assertTrue($systemAdministrator->can('admin.access'));
        $this->assertFalse($systemAdministrator->can('users.read'));
    }

    #[Test]
    public function it_resolves_dotless_permission_names(): void
    {
        $systemAdministrator = $this->createSystemAdministrator();

        $this->assertTrue($systemAdministrator->can('access admin panel'));
        $this->assertFalse($systemAdministrator->can('edit system settings'));
    }

    #[Test]
    public function it_grants_super_admins_every_permission(): void
    {
        $superAdmin = $this->createSuperAdmin();

        $this->assertTrue($superAdmin->hasOrganizationPermission('organizations.update'));
        $this->assertTrue($superAdmin->hasOrganizationPermission('nonexistent.permission'));
    }

    private function createSystemAdministrator(): User
    {
        $this->seed(RolePermissionSeeder::class);
        $user = User::factory()->create(['organization_id' => null]);
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId(null);
        $user->assignRole(Role::where('name', 'System Administrator')->where('guard_name', 'web')->whereNull('organization_id')->firstOrFail());
        $registrar->setPermissionsTeamId($this->createOrganization()->id);

        return $user->fresh();
    }

    private function clearAmbientTeam(User $user): void
    {
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $user->unsetRelation('roles')->unsetRelation('permissions');
    }
}
