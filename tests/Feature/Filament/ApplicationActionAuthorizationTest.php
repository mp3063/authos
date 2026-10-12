<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\ApplicationGroupResource\Pages\ListApplicationGroups;
use App\Filament\Resources\ApplicationResource\Pages\ListApplications;
use App\Filament\Resources\ApplicationResource\Pages\ViewApplication;
use App\Filament\Resources\Invitations\Pages\ListInvitations;
use App\Filament\Resources\SocialAccounts\Pages\ListSocialAccounts;
use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\Organization;
use App\Models\SocialAccount;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class ApplicationActionAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    private function actingAsRole(string $role): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], $role));
    }

    #[Test]
    public function it_hides_and_forbids_regenerate_secret_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $secret = $application->client_secret;

        $list = Livewire::test(ListApplications::class)->assertTableActionHidden('regenerate_secret', $application);
        $this->forceTableAction($list, 'regenerate_secret', $application);

        $view = Livewire::test(ViewApplication::class, ['record' => $application->getRouteKey()])->assertActionHidden('regenerate_secret');
        $this->forcePageAction($view, 'regenerate_secret');

        $this->assertSame($secret, $application->fresh()->client_secret);
    }

    #[Test]
    public function an_application_manager_can_regenerate_a_secret(): void
    {
        $this->actingAsRole('Application Manager');
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $secret = $application->client_secret;

        Livewire::test(ListApplications::class)
            ->assertTableActionVisible('regenerate_secret', $application)
            ->callTableAction('regenerate_secret', $application);

        $this->assertNotSame($secret, $application->fresh()->client_secret);
    }

    #[Test]
    public function it_forbids_application_bulk_activate_and_deactivate_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');
        $application = Application::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true]);
        $inactive = Application::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);

        Livewire::test(ListApplications::class)
            ->callTableBulkAction('deactivate', [$application])
            ->callTableBulkAction('activate', [$inactive])
            ->assertTableBulkActionHidden('delete');

        $this->assertTrue($application->fresh()->is_active);
        $this->assertFalse($inactive->fresh()->is_active);
    }

    #[Test]
    public function it_forbids_group_bulk_actions_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');
        $group = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true]);
        $inactive = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);

        Livewire::test(ListApplicationGroups::class)
            ->callTableBulkAction('deactivate', [$group])
            ->callTableBulkAction('activate', [$inactive])
            ->callTableBulkAction('delete', [$group, $inactive]);

        $this->assertTrue($group->fresh()->is_active);
        $this->assertFalse($inactive->fresh()->is_active);
        $this->assertNotNull(ApplicationGroup::find($group->id));
        $this->assertNotNull(ApplicationGroup::find($inactive->id));
    }

    #[Test]
    public function an_owner_can_run_group_bulk_actions(): void
    {
        $this->actingAsRole('Organization Owner');
        $group = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true]);

        Livewire::test(ListApplicationGroups::class)
            ->callTableBulkAction('deactivate', [$group])
            ->callTableBulkAction('delete', [$group]);

        $this->assertNull(ApplicationGroup::find($group->id));
    }

    #[Test]
    public function it_forbids_the_invitation_list_and_its_actions_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');

        Livewire::test(ListInvitations::class)->assertForbidden();
    }

    #[Test]
    public function it_hides_social_account_bulk_delete_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Member');

        Livewire::test(ListSocialAccounts::class)->assertTableBulkActionHidden('delete');
    }

    #[Test]
    public function an_admin_bulk_deleting_social_accounts_of_their_organization_succeeds(): void
    {
        $this->actingAsRole('Organization Admin');
        $user = $this->createUser(['organization_id' => $this->organization->id], 'User');
        $account = SocialAccount::factory()->create(['user_id' => $user->id]);

        Livewire::test(ListSocialAccounts::class)->callTableBulkAction('delete', [$account]);

        $this->assertNull(SocialAccount::find($account->id));
    }
}
