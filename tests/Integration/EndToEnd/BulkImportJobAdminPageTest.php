<?php

namespace Tests\Integration\EndToEnd;

use App\Models\BulkImportJob;
use PHPUnit\Framework\Attributes\Test;

class BulkImportJobAdminPageTest extends EndToEndTestCase
{
    #[Test]
    public function super_admin_can_open_a_bulk_import_job_view_page(): void
    {
        $job = BulkImportJob::factory()->create([
            'organization_id' => $this->superAdmin->organization_id,
            'created_by' => $this->superAdmin->id,
        ]);

        $this->actingAs($this->superAdmin, 'web')
            ->get("/admin/bulk-import-jobs/{$job->id}")
            ->assertOk();
    }
}
