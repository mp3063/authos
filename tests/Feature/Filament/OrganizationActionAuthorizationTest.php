<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\OrganizationResource\Pages\ListOrganizations;
use App\Filament\Resources\OrganizationResource\Pages\ViewOrganization;
use App\Filament\Resources\OrganizationResource\RelationManagers\ApplicationsRelationManager;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class OrganizationActionAuthorizationTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization(['is_active' => true]);
    }

    private function actingAsRole(string $role): User
    {
        $user = $this->createUser(['organization_id' => $this->organization->id], $role);
        $this->actingAs($user);

        return $user;
    }

    #[Test]
    public function it_forbids_toggle_status_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');

        Livewire::test(ListOrganizations::class)
            ->callTableBulkAction('toggle_status', [$this->organization]);

        $this->assertTrue($this->organization->fresh()->is_active);
    }

    #[Test]
    public function an_owner_can_toggle_the_status_of_their_organization(): void
    {
        $this->actingAsRole('Organization Owner');

        Livewire::test(ListOrganizations::class)
            ->callTableBulkAction('toggle_status', [$this->organization]);

        $this->assertFalse($this->organization->fresh()->is_active);
    }

    #[Test]
    public function it_forbids_bulk_delete_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Owner');

        Livewire::test(ListOrganizations::class)
            ->callTableBulkAction('delete', [$this->organization]);

        $this->assertNotNull(Organization::find($this->organization->id));
    }

    #[Test]
    public function a_super_admin_can_bulk_delete_organizations(): void
    {
        $this->actingAs($this->createSuperAdmin());

        Livewire::test(ListOrganizations::class)
            ->callTableBulkAction('delete', [$this->organization]);

        $this->assertNull(Organization::find($this->organization->id));
    }

    #[Test]
    public function it_forbids_deleting_applications_in_bulk_from_the_organization_page_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);

        Livewire::test(ApplicationsRelationManager::class, ['ownerRecord' => $this->organization, 'pageClass' => ViewOrganization::class])
            ->assertTableBulkActionHidden('delete');

        $this->assertNotNull(Application::find($application->id));
    }
}
