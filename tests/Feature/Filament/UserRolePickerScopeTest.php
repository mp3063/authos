<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\UserResource\Pages\EditUser;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\UserRoleService;
use Filament\Forms\Components\Select;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class UserRolePickerScopeTest extends IntegrationTestCase
{
    private Organization $organizationA;

    private Organization $organizationB;

    private User $member;

    private Role $foreignRole;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organizationA = $this->createOrganization();
        $this->organizationB = $this->createOrganization();
        $this->member = User::factory()->create(['organization_id' => $this->organizationA->id]);
        $this->foreignRole = $this->webRole($this->organizationB, 'Organization Member');
        app(UserRoleService::class)->assignRole($this->member, (string) $this->foreignRole->id);
    }

    #[Test]
    public function it_hides_roles_the_user_holds_in_other_organizations(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organizationA->id], 'Organization Owner'));

        Livewire::test(EditUser::class, ['record' => $this->member->getRouteKey()])
            ->assertFormFieldExists('roles', fn (Select $field): bool => ! in_array($this->foreignRole->id, $field->getState())
                && ! array_key_exists($this->foreignRole->id, $field->getOptions()));
    }

    #[Test]
    public function it_keeps_roles_from_other_organizations_when_saving(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organizationA->id], 'Organization Owner'));
        $organizationRole = $this->webRole($this->organizationA, 'Organization Member');

        Livewire::test(EditUser::class, ['record' => $this->member->getRouteKey()])
            ->fillForm(['roles' => [$organizationRole->id]])
            ->call('save')
            ->assertHasNoFormErrors();

        $this->assertEqualsCanonicalizing(
            [$this->foreignRole->id, $organizationRole->id],
            app(UserRoleService::class)->assignedRoleIds($this->member)->all()
        );
    }

    #[Test]
    public function it_keeps_other_organizations_roles_when_a_super_admin_saves(): void
    {
        $superAdmin = $this->createSuperAdmin();
        $superAdmin->update(['organization_id' => null]);
        $this->actingAs($superAdmin);
        $organizationRole = $this->webRole($this->organizationA, 'Organization Member');

        Livewire::test(EditUser::class, ['record' => $this->member->getRouteKey()])
            ->fillForm(['roles' => [$organizationRole->id]])
            ->call('save')
            ->assertHasNoFormErrors();

        $this->assertEqualsCanonicalizing(
            [$this->foreignRole->id, $organizationRole->id],
            app(UserRoleService::class)->assignedRoleIds($this->member)->all()
        );
        $this->assertDatabaseHas('model_has_roles', [
            'model_id' => $this->member->id,
            'role_id' => $this->foreignRole->id,
            'organization_id' => $this->organizationB->id,
        ]);
        $this->assertDatabaseHas('model_has_roles', [
            'model_id' => $this->member->id,
            'role_id' => $organizationRole->id,
            'organization_id' => $this->organizationA->id,
        ]);
    }

    private function webRole(Organization $organization, string $name): Role
    {
        return Role::where('name', $name)
            ->where('organization_id', $organization->id)
            ->where('guard_name', 'web')
            ->firstOrFail();
    }
}
