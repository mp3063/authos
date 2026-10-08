<?php

namespace Tests\Integration\BulkOperations;

use App\Models\BulkImportJob;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class BulkJobPermissionGuardsTest extends IntegrationTestCase
{
    #[Test]
    public function it_forbids_a_plain_user_with_a_star_token_from_deleting_a_bulk_import_job_with_403(): void
    {
        $user = $this->createApiUser();
        $job = BulkImportJob::factory()->create(['organization_id' => $user->organization_id]);
        $this->actingAsApiUserWithToken($user, ['*']);

        $this->deleteJson("/api/v1/bulk/imports/{$job->id}")->assertForbidden();
        $this->postJson("/api/v1/bulk/imports/{$job->id}/cancel")->assertForbidden();
        $this->postJson("/api/v1/bulk/imports/{$job->id}/retry")->assertForbidden();
        $this->assertDatabaseHas('bulk_import_jobs', ['id' => $job->id]);
    }

    #[Test]
    public function it_removes_the_unscoped_mock_job_status_route(): void
    {
        $user = $this->createApiUser();
        $this->actingAsApiUserWithToken($user, ['*']);

        $this->getJson('/api/v1/bulk/jobs/'.fake()->uuid())->assertNotFound();
    }
}
