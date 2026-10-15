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
        $state = Livewire::test(CreateRole::class)
            ->fillForm(['guard_name' => 'web', 'permission_template' => 'Organization Member'])
            ->get('data.permissions');

        $this->assertEqualsCanonicalizing(
            $this->globalWebPermissionIds(['users.read', 'applications.read', 'organizations.read']),
            $state,
        );
    }

    #[Test]
    public function it_ticks_every_available_permission_for_the_super_admin_template(): void
    {
        $state = Livewire::test(CreateRole::class)
            ->fillForm(['guard_name' => 'web', 'permission_template' => 'Super Admin'])
            ->get('data.permissions');

        $this->assertEqualsCanonicalizing(
            $this->globalWebPermissionIds(),
            $state,
        );
    }

    #[Test]
    public function it_saves_the_template_permissions_with_the_role(): void
    {
        Livewire::test(CreateRole::class)
            ->fillForm(['name' => 'Readers', 'guard_name' => 'web', 'permission_template' => 'Organization Member'])
            ->call('create')
            ->assertHasNoFormErrors();

        $this->assertDatabaseHas('role_has_permissions', ['permission_id' => $this->globalWebPermissionIds(['users.read'])[0]]);
    }

    /**
     * @param  list<string>|null  $names
     * @return list<string>
     */
    private function globalWebPermissionIds(?array $names = null): array
    {
        return Permission::where('guard_name', 'web')
            ->whereNull('organization_id')
            ->when($names !== null, fn ($query) => $query->whereIn('name', $names))
            ->pluck('id')
            ->map(fn ($id): string => (string) $id)
            ->all();
    }
}
