<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\BulkImportJobResource\Pages\ListBulkImportJobs;
use App\Filament\Resources\BulkImportJobResource\Pages\ViewBulkImportJob;
use App\Filament\Resources\MigrationJobResource\Pages\ListMigrationJobs;
use App\Filament\Resources\MigrationJobResource\Pages\ViewMigrationJob;
use App\Jobs\ProcessAuth0MigrationJob;
use App\Models\BulkImportJob;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Queue;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class OperationsActionAuthorizationTest extends IntegrationTestCase
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

    /**
     * @return array<string, array{0: string}>
     */
    public static function readOnlyRoles(): array
    {
        return [
            'auditor' => ['Auditor'],
            'custom role' => ['custom'],
        ];
    }

    private function actingAsReadOnly(string $kind, string $readPermission): void
    {
        if ($kind === 'custom') {
            $this->actingAs($this->createUserWithCustomPermissions($this->organization, ['admin.access', $readPermission]));

            return;
        }

        $this->actingAsRole($kind);
    }

    #[Test]
    #[DataProvider('readOnlyRoles')]
    public function it_hides_and_forbids_bulk_import_retry_and_cancel_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsReadOnly($kind, 'users.read');
        Queue::fake();
        $failed = BulkImportJob::factory()->failed()->create(['organization_id' => $this->organization->id]);
        $running = BulkImportJob::factory()->processing()->create(['organization_id' => $this->organization->id]);

        $list = Livewire::test(ListBulkImportJobs::class)
            ->assertTableActionHidden('retry', $failed)
            ->assertTableActionHidden('cancel', $running);
        $this->forceTableAction($list, 'retry', $failed);
        $this->forceTableAction($list, 'cancel', $running);

        $viewFailed = Livewire::test(ViewBulkImportJob::class, ['record' => $failed->getRouteKey()])->assertActionHidden('retry');
        $this->forcePageAction($viewFailed, 'retry');
        $viewRunning = Livewire::test(ViewBulkImportJob::class, ['record' => $running->getRouteKey()])->assertActionHidden('cancel');
        $this->forcePageAction($viewRunning, 'cancel');

        $this->assertSame(BulkImportJob::STATUS_FAILED, $failed->fresh()->status);
        $this->assertSame(BulkImportJob::STATUS_PROCESSING, $running->fresh()->status);
        Queue::assertNothingPushed();
    }

    #[Test]
    public function an_admin_can_retry_and_cancel_bulk_import_jobs(): void
    {
        $this->actingAsRole('Organization Admin');
        $failed = BulkImportJob::factory()->failed()->create(['organization_id' => $this->organization->id]);
        $running = BulkImportJob::factory()->processing()->create(['organization_id' => $this->organization->id]);

        Livewire::test(ListBulkImportJobs::class)
            ->assertTableActionVisible('retry', $failed)
            ->callTableAction('retry', $failed)
            ->callTableAction('cancel', $running);

        $this->assertSame(BulkImportJob::STATUS_PENDING, $failed->fresh()->status);
        $this->assertSame(BulkImportJob::STATUS_CANCELLED, $running->fresh()->status);
    }

    #[Test]
    #[DataProvider('readOnlyRoles')]
    public function it_hides_and_forbids_migration_actions_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsReadOnly($kind, 'organizations.read');
        Queue::fake();
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $failed = MigrationJob::factory()->failed()->create(['organization_id' => $this->organization->id]);
        $completed = MigrationJob::factory()->completed()->create(['organization_id' => $this->organization->id]);

        $list = Livewire::test(ListMigrationJobs::class)
            ->assertActionHidden('new_migration')
            ->assertTableActionHidden('retry', $failed)
            ->assertTableActionHidden('rollback', $completed);
        $this->forceTableAction($list, 'retry', $failed);
        $this->forceTableAction($list, 'rollback', $completed);
        $this->forcePageAction($list, 'new_migration');

        $viewFailed = Livewire::test(ViewMigrationJob::class, ['record' => $failed->getRouteKey()])->assertActionHidden('retry');
        $this->forcePageAction($viewFailed, 'retry');
        $viewCompleted = Livewire::test(ViewMigrationJob::class, ['record' => $completed->getRouteKey()])->assertActionHidden('rollback');
        $this->forcePageAction($viewCompleted, 'rollback');

        $this->assertSame('failed', $failed->fresh()->status);
        $this->assertSame('completed', $completed->fresh()->status);
        $this->assertNotNull(User::find($member->id));
        $this->assertSame(2, MigrationJob::count());
        Queue::assertNothingPushed();
    }

    #[Test]
    public function an_owner_can_retry_but_not_start_or_roll_back_migrations(): void
    {
        $this->actingAsRole('Organization Owner');
        Queue::fake();
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $failed = MigrationJob::factory()->failed()->create(['organization_id' => $this->organization->id]);
        $completed = MigrationJob::factory()->completed()->create(['organization_id' => $this->organization->id]);

        $list = Livewire::test(ListMigrationJobs::class)
            ->assertActionHidden('new_migration')
            ->assertTableActionHidden('rollback', $completed)
            ->callTableAction('retry', $failed);
        $this->forcePageAction($list, 'new_migration');
        $this->forceTableAction($list, 'rollback', $completed);

        $viewCompleted = Livewire::test(ViewMigrationJob::class, ['record' => $completed->getRouteKey()])->assertActionHidden('rollback');
        $this->forcePageAction($viewCompleted, 'rollback');

        $this->assertSame('pending', $failed->fresh()->status);
        $this->assertSame('completed', $completed->fresh()->status);
        $this->assertNotNull(User::find($member->id));
        $this->assertSame(2, MigrationJob::count());
        Queue::assertNothingPushed();
    }

    #[Test]
    public function a_super_admin_can_start_and_roll_back_migrations(): void
    {
        $this->actingAs($this->createSuperAdmin());
        Queue::fake();
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $completed = MigrationJob::factory()->completed()->create(['organization_id' => $this->organization->id]);

        Livewire::test(ListMigrationJobs::class)
            ->assertActionVisible('new_migration')
            ->callAction('new_migration', [
                'source' => 'auth0',
                'organization_id' => $this->organization->id,
                'tenant_domain' => 'tenant.auth0.com',
                'api_token' => 'token',
            ])
            ->callTableAction('rollback', $completed);

        $this->assertSame('rolled_back', $completed->fresh()->status);
        $this->assertNull(User::find($member->id));
        $this->assertSame(2, MigrationJob::where('organization_id', $this->organization->id)->count());
        Queue::assertPushed(ProcessAuth0MigrationJob::class);
    }
}
