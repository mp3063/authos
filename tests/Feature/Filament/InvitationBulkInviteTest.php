<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\Invitations\Pages\ListInvitations;
use App\Models\Invitation;
use App\Models\Organization;
use App\Services\InvitationService;
use Filament\Notifications\Notification;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Mail;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Tests\Integration\IntegrationTestCase;

class InvitationBulkInviteTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();
        $this->organization = $this->createOrganization();
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Admin', 'web'));
    }

    private function csvPath(): string
    {
        $name = 'csv-imports/bulk-'.uniqid().'.csv';
        $path = storage_path('app/private/'.$name);
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, "email,role\nfirst@example.com,Organization Member\nsecond@example.com,Organization Member\n");
        $this->beforeApplicationDestroyed(fn () => @unlink($path));

        return $name;
    }

    #[Test]
    public function it_reports_the_number_of_invitations_sent_by_the_csv_bulk_invite(): void
    {
        Livewire::test(ListInvitations::class)
            ->callAction('bulkCsvInvite', ['organization_id' => $this->organization->id, 'csv_file' => [$this->csvPath()]])
            ->assertNotified('Bulk invite complete: 2 sent, 0 failed');
    }

    #[Test]
    public function it_does_not_show_raw_exception_text_in_the_bulk_invite_notification(): void
    {
        $this->mock(InvitationService::class)
            ->shouldReceive('bulkInvite')
            ->andThrow(new RuntimeException('SQLSTATE secret detail'));
        Exceptions::fake();

        Livewire::test(ListInvitations::class)
            ->callAction('bulkCsvInvite', ['organization_id' => $this->organization->id, 'csv_file' => [$this->csvPath()]])
            ->assertNotified(
                Notification::make()
                    ->title('Bulk invite failed')
                    ->body('The invitations could not be sent. Please try again or contact an administrator.')
                    ->danger()
            );

        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'SQLSTATE secret detail');
    }

    #[Test]
    public function it_authorizes_bulk_delete_per_record(): void
    {
        $own = Invitation::factory()->forOrganization($this->organization)->create();
        $refused = Invitation::factory()->forOrganization($this->organization)->create();
        Gate::before(fn ($user, string $ability, array $arguments): ?bool => $ability === 'delete' && ($arguments[0] ?? null)?->is($refused) ? false : null);

        Livewire::test(ListInvitations::class)
            ->callTableBulkAction('delete', [$own, $refused]);

        $this->assertModelMissing($own);
        $this->assertModelExists($refused);
    }

    #[Test]
    public function it_refuses_the_invitations_list_to_a_role_without_users_create(): void
    {
        $invitation = Invitation::factory()->forOrganization($this->organization)->create();
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Auditor', 'web'));

        Livewire::test(ListInvitations::class)->assertForbidden();

        $this->assertModelExists($invitation);
    }
}
