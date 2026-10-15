<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\RoleResource\Pages\CreateRole;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Models\Permission;
use Tests\Integration\IntegrationTestCase;

class RolePermissionTemplateTest extends IntegrationTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->actingAs($this->createSuperAdmin());
    }

    #[Test]
    public function it_ticks_the_permissions_of_the_chosen_default_role(): void
    {
        $usersRead = Permission::findOrCreate('users.read', 'web');
        $applicationsRead = Permission::findOrCreate('applications.read', 'web');
        Permission::findOrCreate('users.delete', 'web');
        Permission::findOrCreate('users.read', 'api');

        $state = Livewire::test(CreateRole::class)
            ->fillForm(['guard_name' => 'web', 'permission_template' => 'Organization Member'])
            ->get('data.permissions');

        $this->assertEqualsCanonicalizing([(string) $usersRead->id, (string) $applicationsRead->id], $state);
    }

    #[Test]
    public function it_ticks_every_available_permission_for_the_super_admin_template(): void
    {
        foreach (['users.read', 'users.delete', 'roles.read'] as $name) {
            Permission::findOrCreate($name, 'web');
        }
        Permission::findOrCreate('users.read', 'api');

        $state = Livewire::test(CreateRole::class)
            ->fillForm(['guard_name' => 'web', 'permission_template' => 'Super Admin'])
            ->get('data.permissions');

        $this->assertEqualsCanonicalizing(
            Permission::where('guard_name', 'web')->whereNull('organization_id')->pluck('id')->map(fn ($id): string => (string) $id)->all(),
            $state,
        );
    }

    #[Test]
    public function it_saves_the_template_permissions_with_the_role(): void
    {
        $usersRead = Permission::findOrCreate('users.read', 'web');

        Livewire::test(CreateRole::class)
            ->fillForm(['name' => 'Readers', 'guard_name' => 'web', 'permission_template' => 'Organization Member'])
            ->call('create')
            ->assertHasNoFormErrors();

        $this->assertDatabaseHas('role_has_permissions', ['permission_id' => $usersRead->id]);
    }
}
