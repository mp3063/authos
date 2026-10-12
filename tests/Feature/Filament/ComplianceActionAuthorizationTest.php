<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\AuditExportResource\Pages\ListAuditExports;
use App\Filament\Resources\ComplianceReportResource\Pages\ListComplianceReports;
use App\Filament\Resources\ScheduledComplianceReportResource\Pages\ListScheduledComplianceReports;
use App\Jobs\GenerateComplianceReportJob;
use App\Models\AuditExport;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use Illuminate\Support\Facades\Bus;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class ComplianceActionAuthorizationTest extends IntegrationTestCase
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
    public static function viewOnlyRoles(): array
    {
        return [
            'admin' => ['Organization Admin'],
            'custom role' => ['custom'],
        ];
    }

    private function actingAsViewOnly(string $kind): void
    {
        if ($kind === 'custom') {
            $this->actingAs($this->createUserWithCustomPermissions($this->organization, ['admin.access', 'auth_logs.read']));

            return;
        }

        $this->actingAsRole($kind);
    }

    #[Test]
    #[DataProvider('viewOnlyRoles')]
    public function it_hides_and_forbids_generate_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsViewOnly($kind);
        Bus::fake();

        $list = Livewire::test(ListComplianceReports::class)->assertActionHidden('generate');
        $list->call('mountAction', 'generate');
        $list->set('mountedActions.0.data.report_type', ComplianceReport::TYPE_SOC2)->call('callMountedAction');

        Bus::assertNothingDispatched();
        $this->assertSame(0, ComplianceReport::count());
    }

    #[Test]
    public function an_owner_can_generate_a_compliance_report(): void
    {
        $this->actingAsRole('Organization Owner');
        Bus::fake();

        Livewire::test(ListComplianceReports::class)
            ->assertActionVisible('generate')
            ->callAction('generate', ['report_type' => ComplianceReport::TYPE_SOC2]);

        Bus::assertDispatchedSync(GenerateComplianceReportJob::class);
    }

    #[Test]
    #[DataProvider('viewOnlyRoles')]
    public function it_hides_and_forbids_run_now_and_delete_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsViewOnly($kind);
        Bus::fake();
        $schedule = ScheduledComplianceReport::factory()->create(['organization_id' => $this->organization->id]);

        $list = Livewire::test(ListScheduledComplianceReports::class)
            ->assertTableActionHidden('runNow', $schedule)
            ->assertTableActionHidden('delete', $schedule);
        $this->forceTableAction($list, 'runNow', $schedule);
        $this->forceTableAction($list, 'delete', $schedule);

        Bus::assertNothingDispatched();
        $this->assertNull($schedule->fresh()->last_run_at);
    }

    #[Test]
    public function an_owner_can_run_a_schedule_now(): void
    {
        $this->actingAsRole('Organization Owner');
        Bus::fake();
        $schedule = ScheduledComplianceReport::factory()->create(['organization_id' => $this->organization->id]);

        Livewire::test(ListScheduledComplianceReports::class)
            ->assertTableActionVisible('runNow', $schedule)
            ->callTableAction('runNow', $schedule);

        Bus::assertDispatched(GenerateComplianceReportJob::class);
        $this->assertNotNull($schedule->fresh()->last_run_at);
    }

    #[Test]
    #[DataProvider('viewOnlyRoles')]
    public function it_hides_and_forbids_audit_export_delete_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsViewOnly($kind);
        $export = AuditExport::factory()->completed()->create(['organization_id' => $this->organization->id]);

        $list = Livewire::test(ListAuditExports::class)
            ->assertTableActionVisible('download', $export)
            ->assertTableActionHidden('delete', $export);
        $this->forceTableAction($list, 'delete', $export);

        $this->assertNotNull(AuditExport::find($export->id));
    }
}
