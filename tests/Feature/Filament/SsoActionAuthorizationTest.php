<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\SSOConfigurationResource\Pages\ListSSOConfigurations;
use App\Filament\Resources\SSOConfigurationResource\Pages\ViewSSOConfiguration;
use App\Filament\Resources\SSOSessionResource\Pages\ListSSOSessions;
use App\Filament\Resources\SSOSessionResource\Pages\ViewSSOSession;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class SsoActionAuthorizationTest extends IntegrationTestCase
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

    private function configuration(bool $active): SSOConfiguration
    {
        return SSOConfiguration::factory()->oidc()->forOrganization($this->organization)->create(['is_active' => $active]);
    }

    #[Test]
    public function it_hides_and_forbids_enable_and_disable_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Admin');
        $inactive = $this->configuration(false);
        $active = $this->configuration(true);

        $list = Livewire::test(ListSSOConfigurations::class)
            ->assertTableActionHidden('enable', $inactive)
            ->assertTableActionHidden('disable', $active);
        $this->forceTableAction($list, 'enable', $inactive);
        $this->forceTableAction($list, 'disable', $active);

        $viewInactive = Livewire::test(ViewSSOConfiguration::class, ['record' => $inactive->getRouteKey()])->assertActionHidden('enable');
        $this->forcePageAction($viewInactive, 'enable');
        $viewActive = Livewire::test(ViewSSOConfiguration::class, ['record' => $active->getRouteKey()])->assertActionHidden('disable');
        $this->forcePageAction($viewActive, 'disable');

        $this->assertFalse($inactive->fresh()->is_active);
        $this->assertTrue($active->fresh()->is_active);
    }

    #[Test]
    public function an_owner_can_enable_and_disable_a_configuration(): void
    {
        $this->actingAsRole('Organization Owner');
        $inactive = $this->configuration(false);
        $active = $this->configuration(true);

        Livewire::test(ListSSOConfigurations::class)
            ->assertTableActionVisible('enable', $inactive)
            ->callTableAction('enable', $inactive)
            ->callTableAction('disable', $active);

        $this->assertTrue($inactive->fresh()->is_active);
        $this->assertFalse($active->fresh()->is_active);
    }

    #[Test]
    public function the_view_page_redacts_secrets_in_the_configuration(): void
    {
        $this->actingAsRole('Auditor');
        $configuration = $this->configuration(true);
        $secret = $configuration->configuration['client_secret'];
        $clientId = $configuration->configuration['client_id'];

        Livewire::test(ViewSSOConfiguration::class, ['record' => $configuration->getRouteKey()])
            ->assertSuccessful()
            ->assertSee($clientId)
            ->assertDontSee($secret);
    }

    #[Test]
    public function it_hides_and_forbids_terminate_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Auditor');
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User');
        $session = SSOSession::factory()->forUser($member)->create();
        $other = SSOSession::factory()->forUser($member)->create();

        $list = Livewire::test(ListSSOSessions::class)->assertTableActionHidden('terminate', $session);
        $this->forceTableAction($list, 'terminate', $session);
        $this->forceTableBulkAction($list, 'terminate', [$other]);

        $view = Livewire::test(ViewSSOSession::class, ['record' => $session->getRouteKey()])->assertActionHidden('terminate');
        $this->forcePageAction($view, 'terminate');

        $this->assertTrue($session->fresh()->isActive());
        $this->assertTrue($other->fresh()->isActive());
    }

    #[Test]
    public function an_admin_can_terminate_a_members_session(): void
    {
        $this->actingAsRole('Organization Admin');
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User');
        $session = SSOSession::factory()->forUser($member)->create();

        Livewire::test(ListSSOSessions::class)
            ->assertTableActionVisible('terminate', $session)
            ->callTableAction('terminate', $session);

        $this->assertFalse($session->fresh()->isActive());
    }
}
