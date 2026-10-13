<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\AuditExportResource\Pages\ListAuditExports;
use App\Filament\Resources\AuditExportResource\Pages\ViewAuditExport;
use App\Models\AuditExport;
use App\Models\Organization;
use Illuminate\Support\Facades\Storage;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class AuditExportDownloadTest extends IntegrationTestCase
{
    private Organization $organization;

    private AuditExport $export;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        $this->organization = $this->createOrganization();
        $this->export = AuditExport::factory()->completed()->create([
            'organization_id' => $this->organization->id,
            'type' => 'csv',
            'file_path' => 'exports/audit-export-test.csv',
        ]);
        Storage::disk('local')->put('exports/audit-export-test.csv', 'id,event');
    }

    #[Test]
    public function it_downloads_a_completed_audit_export_from_the_panel(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Owner'));

        Livewire::test(ListAuditExports::class)
            ->assertTableActionVisible('download', $this->export)
            ->callTableAction('download', $this->export)
            ->assertFileDownloaded('audit-export-test.csv', 'id,event');

        Livewire::test(ViewAuditExport::class, ['record' => $this->export->getRouteKey()])
            ->assertActionVisible('download')
            ->callAction('download')
            ->assertFileDownloaded('audit-export-test.csv', 'id,event');
    }

    #[Test]
    public function it_refuses_the_download_to_a_user_who_cannot_view_the_export(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'User'));

        Livewire::test(ListAuditExports::class)->assertForbidden();
        Livewire::test(ViewAuditExport::class, ['record' => $this->export->getRouteKey()])->assertForbidden();
    }
}
