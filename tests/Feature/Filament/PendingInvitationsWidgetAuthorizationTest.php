<?php

namespace Tests\Feature\Filament;

use App\Filament\Widgets\PendingInvitationsWidget;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class PendingInvitationsWidgetAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    private Organization $otherOrganization;

    private Invitation $own;

    private Invitation $foreign;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->otherOrganization = $this->createOrganization();
        $this->own = Invitation::factory()->forOrganization($this->organization)->create();
        $this->foreign = Invitation::factory()->forOrganization($this->otherOrganization)->create();
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Admin', 'web'));
    }

    private function denyInvitationAbilities(): void
    {
        Gate::before(fn (User $user, string $ability, array $arguments) => ($arguments[0] ?? null) instanceof Invitation ? false : null);
    }

    #[Test]
    public function it_authorizes_each_invitation_in_widget_bulk_actions(): void
    {
        $before = $this->foreign->fresh()->only(['expires_at', 'metadata']);

        $component = Livewire::test(PendingInvitationsWidget::class);
        $this->forceTableBulkAction($component, 'resend_selected', [$this->foreign]);
        $this->forceTableBulkAction($component, 'extend_selected', [$this->foreign]);
        $this->forceTableBulkAction($component, 'cancel_selected', [$this->foreign]);

        $this->assertNotNull(Invitation::find($this->foreign->id));
        $this->assertEquals($before, $this->foreign->fresh()->only(['expires_at', 'metadata']));
    }

    #[Test]
    public function it_skips_invitations_the_policy_denies_in_bulk_actions(): void
    {
        $this->denyInvitationAbilities();
        $before = $this->own->fresh()->only(['expires_at', 'metadata']);

        $component = Livewire::test(PendingInvitationsWidget::class);
        $this->forceTableBulkAction($component, 'resend_selected', [$this->own]);
        $this->forceTableBulkAction($component, 'extend_selected', [$this->own]);
        $this->forceTableBulkAction($component, 'cancel_selected', [$this->own]);

        $this->assertNotNull(Invitation::find($this->own->id));
        $this->assertEquals($before, $this->own->fresh()->only(['expires_at', 'metadata']));
    }

    #[Test]
    public function it_forbids_record_actions_the_policy_denies(): void
    {
        $this->denyInvitationAbilities();
        $before = $this->own->fresh()->only(['expires_at', 'metadata']);

        $component = Livewire::test(PendingInvitationsWidget::class);
        foreach (['resend', 'extend', 'copy_link', 'cancel'] as $action) {
            $component->assertTableActionHidden($action, $this->own);
            $this->forceTableAction($component, $action, $this->own);
        }

        $this->assertNotNull(Invitation::find($this->own->id));
        $this->assertEquals($before, $this->own->fresh()->only(['expires_at', 'metadata']));
    }

    #[Test]
    public function it_still_runs_the_actions_for_authorized_invitations(): void
    {
        $component = Livewire::test(PendingInvitationsWidget::class);
        $this->forceTableBulkAction($component, 'cancel_selected', [$this->own]);

        $this->assertNull(Invitation::find($this->own->id));
        $this->assertNotNull(Invitation::find($this->foreign->id));
    }

    #[Test]
    public function it_refuses_copy_link_to_a_caller_who_may_not_update_the_invitation(): void
    {
        $this->denyInvitationAbilities();

        $component = Livewire::test(PendingInvitationsWidget::class);
        $component->assertTableActionHidden('copy_link', $this->own);
        $this->forceTableAction($component, 'copy_link', $this->own)->assertNotDispatched('copy-to-clipboard');
    }
}
