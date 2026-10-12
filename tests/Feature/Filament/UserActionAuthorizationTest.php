<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\UserResource\Pages\ListUsers;
use App\Filament\Resources\UserResource\Pages\ViewUser;
use App\Filament\Resources\UserResource\RelationManagers\ApplicationsRelationManager;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class UserActionAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    private User $member;

    private User $target;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->member = $this->createUser(['organization_id' => $this->organization->id], 'User');
        $this->target = $this->createUser([
            'organization_id' => $this->organization->id,
            'mfa_methods' => ['totp'],
            'email_verified_at' => null,
        ], 'User');
        $this->actingAs($this->member);
    }

    #[Test]
    public function it_hides_and_forbids_reset_mfa_for_a_role_without_the_permission(): void
    {
        $list = Livewire::test(ListUsers::class)->assertTableActionHidden('reset_mfa', $this->target);
        $this->forceTableAction($list, 'reset_mfa', $this->target);

        $view = Livewire::test(ViewUser::class, ['record' => $this->target->getRouteKey()])->assertActionHidden('reset_mfa');
        $this->forcePageAction($view, 'reset_mfa');

        $this->assertNotEmpty($this->target->fresh()->mfa_methods);
    }

    #[Test]
    public function it_hides_and_forbids_force_verify_email_for_a_role_without_the_permission(): void
    {
        $list = Livewire::test(ListUsers::class)->assertTableActionHidden('force_verify_email', $this->target);
        $this->forceTableAction($list, 'force_verify_email', $this->target);

        $this->assertNull($this->target->fresh()->email_verified_at);
    }

    #[Test]
    public function it_forbids_verify_emails_for_a_role_without_the_permission(): void
    {
        Livewire::test(ListUsers::class)
            ->callTableBulkAction('verify_emails', [$this->target]);

        $this->assertNull($this->target->fresh()->email_verified_at);
    }

    #[Test]
    public function it_forbids_bulk_reset_mfa_for_a_role_without_the_permission(): void
    {
        Livewire::test(ListUsers::class)
            ->callTableBulkAction('reset_mfa', [$this->target]);

        $this->assertNotEmpty($this->target->fresh()->mfa_methods);
    }

    #[Test]
    public function it_hides_bulk_delete_for_a_role_without_the_permission(): void
    {
        Livewire::test(ListUsers::class)
            ->assertTableBulkActionHidden('delete');
    }

    #[Test]
    public function an_owner_bulk_deleting_themselves_and_a_peer_only_deletes_the_peer(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner');
        $peer = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner');
        $this->actingAs($owner);

        Livewire::test(ListUsers::class)
            ->callTableBulkAction('delete', [$owner, $peer]);

        $this->assertNotNull(User::find($owner->id));
        $this->assertNull(User::find($peer->id));
    }

    #[Test]
    public function an_owner_can_run_user_actions(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner');
        $this->actingAs($owner);

        Livewire::test(ListUsers::class)
            ->assertTableActionVisible('reset_mfa', $this->target)
            ->callTableAction('reset_mfa', $this->target)
            ->callTableAction('force_verify_email', $this->target);

        $this->assertEmpty($this->target->fresh()->mfa_methods);
        $this->assertNotNull($this->target->fresh()->email_verified_at);
    }

    #[Test]
    public function it_hides_and_forbids_attach_and_detach_applications_for_a_role_without_the_permission(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $this->target->applications()->attach($application->id);

        $component = Livewire::test(ApplicationsRelationManager::class, ['ownerRecord' => $this->target, 'pageClass' => ViewUser::class])
            ->assertTableActionHidden('attach')
            ->assertTableActionHidden('detach', $application)
            ->assertTableBulkActionHidden('detach');
        $this->forceTableAction($component, 'detach', $application);

        $this->assertTrue($this->target->applications()->whereKey($application->id)->exists());
    }
}
