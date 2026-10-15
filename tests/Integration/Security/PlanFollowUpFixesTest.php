<?php

namespace Tests\Integration\Security;

use App\Imports\UsersImport;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\Migration\Importers\OrganizationImporter;
use App\Services\InvitationService;
use App\Services\UserRoleService;
use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class PlanFollowUpFixesTest extends IntegrationTestCase
{
    #[Test]
    public function it_gives_imported_auth0_organizations_a_unique_slug(): void
    {
        $dto = fn (string $id, string $name) => new Auth0OrganizationDTO($id, $name, 'Acme Corp', [], []);

        $result = (new OrganizationImporter)->import([
            $dto('org_1', 'Acme Corp'),
            $dto('org_2', 'acme-corp'),
        ]);

        $this->assertSame(2, $result->getSuccessCount());
        $this->assertSame(
            ['acme-corp', 'acme-corp-2'],
            Organization::orderBy('id')->pluck('slug')->all()
        );
    }

    #[Test]
    public function it_resolves_user_import_roles_on_the_api_guard_only(): void
    {
        $organization = $this->createOrganization();
        $admin = $this->createSuperAdmin();
        Role::create(['name' => 'Reviewer', 'guard_name' => 'web', 'organization_id' => $organization->id]);
        $apiRole = Role::create(['name' => 'Reviewer', 'guard_name' => 'api', 'organization_id' => $organization->id]);

        $import = new UsersImport(
            $organization,
            $admin,
            false,
            'Reviewer',
            false,
            app(InvitationService::class),
            app(UserRoleService::class)
        );
        $import->collection(new Collection([collect(['email' => 'new@example.com', 'name' => 'New User', 'role' => 'Reviewer', 'password' => 'Str0ng-Passw0rd!'])]));

        $user = User::where('email', 'new@example.com')->firstOrFail();
        $this->assertSame([$apiRole->id], $user->roles()->pluck('roles.id')->all());
    }
}
