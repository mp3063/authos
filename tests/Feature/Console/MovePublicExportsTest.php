<?php

namespace Tests\Feature\Console;

use App\Models\AuditExport;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class MovePublicExportsTest extends IntegrationTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('public');
        Storage::fake('local');
    }

    #[Test]
    public function referenced_exports_are_moved_to_the_local_disk(): void
    {
        $export = AuditExport::factory()->create(['file_path' => 'exports/audit-export-1-2026.csv']);
        Storage::disk('public')->put($export->file_path, 'secret,data');

        $this->artisan('exports:move-public')->assertSuccessful();

        Storage::disk('public')->assertMissing($export->file_path);
        $this->assertSame('secret,data', Storage::disk('local')->get($export->file_path));
    }

    #[Test]
    public function unreferenced_public_exports_are_deleted(): void
    {
        Storage::disk('public')->put('exports/org-1-users-2026.json', '[]');

        $this->artisan('exports:move-public')->assertSuccessful();

        Storage::disk('public')->assertMissing('exports/org-1-users-2026.json');
        Storage::disk('local')->assertMissing('exports/org-1-users-2026.json');
    }

    #[Test]
    public function an_existing_local_copy_is_not_overwritten(): void
    {
        $export = AuditExport::factory()->create(['file_path' => 'exports/audit-export-2-2026.json']);
        Storage::disk('public')->put($export->file_path, 'stale');
        Storage::disk('local')->put($export->file_path, 'current');

        $this->artisan('exports:move-public')->assertSuccessful();

        Storage::disk('public')->assertMissing($export->file_path);
        $this->assertSame('current', Storage::disk('local')->get($export->file_path));
    }

    #[Test]
    public function dry_run_changes_nothing(): void
    {
        $export = AuditExport::factory()->create(['file_path' => 'exports/audit-export-3-2026.csv']);
        Storage::disk('public')->put($export->file_path, 'data');
        Storage::disk('public')->put('exports/orphan.csv', 'data');

        $this->artisan('exports:move-public', ['--dry-run' => true])->assertSuccessful();

        Storage::disk('public')->assertExists([$export->file_path, 'exports/orphan.csv']);
        Storage::disk('local')->assertMissing($export->file_path);
    }
}
