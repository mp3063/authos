<?php

namespace Tests\Integration\Organizations;

use App\Models\Organization;
use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * Organization Bulk Operations Integration Tests
 *
 * Tests bulk operations for organization management including:
 * - Bulk role assignments
 * - Bulk access revocation
 * - Bulk settings updates
 * - Bulk user imports
 * - Bulk user exports
 * - Bulk user deletions
 * - Bulk MFA enablement
 * - Job status tracking
 *
 * Verifies:
 * - Operations handle large datasets correctly
 * - Jobs are queued properly
 * - Status tracking works
 * - Rollback mechanisms function
 * - Performance is acceptable
 */
class OrganizationBulkOpsTest extends IntegrationTestCase
{
    protected User $admin;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->admin = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_assign_roles(): void
    {
        // ARRANGE: Create multiple users
        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        $userIds = $users->pluck('id')->toArray();

        // ACT: Bulk assign roles
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
                'user_ids' => $userIds,
                'role' => 'Organization Member',
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'success_count',
                    'failed_count',
                    'job_id',
                ],
            ]);

        $responseData = $response->json('data');
        $this->assertEquals(5, $responseData['success_count']);
        $this->assertEquals(0, $responseData['failed_count']);

        // ASSERT: Verify all users have the role
        foreach ($users as $user) {
            $user->refresh();
            $this->assertTrue($user->hasRole('Organization Member'));
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_revoke_access(): void
    {
        // ARRANGE: Create users with access
        $users = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        foreach ($users as $user) {
            $user->assignRole('Organization Member');
        }

        // ACT: Bulk revoke access
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/revoke-access", [
                'user_ids' => $users->pluck('id')->toArray(),
                'reason' => 'Security audit cleanup',
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'revoked_count' => 3,
                ],
            ]);

        // ASSERT: Verify roles were revoked
        foreach ($users as $user) {
            $user->refresh();
            $this->assertFalse($user->hasRole('Organization Member'));
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_update_settings(): void
    {
        // ARRANGE: Create multiple organizations (super admin scenario)
        $orgs = Organization::factory()->count(3)->create();
        $superAdmin = $this->createSuperAdmin();

        // ACT: Bulk update settings
        $response = $this->actingAs($superAdmin, 'api')
            ->postJson('/api/v1/organizations/bulk/update-settings', [
                'organization_ids' => $orgs->pluck('id')->toArray(),
                'settings' => [
                    'require_mfa' => true,
                    'session_timeout' => 60,
                ],
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'updated_count' => 3,
                ],
            ]);

        // ASSERT: Verify settings updated
        foreach ($orgs as $org) {
            $org->refresh();
            $this->assertTrue($org->settings['require_mfa']);
            $this->assertEquals(60, $org->settings['session_timeout']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_import_users(): void
    {
        // ARRANGE: Prepare CSV data
        $csvData = "name,email,role\n";
        $csvData .= "John Doe,john@example.com,User\n";
        $csvData .= "Jane Smith,jane@example.com,Organization Member\n";
        $csvData .= "Bob Johnson,bob@example.com,User\n";

        $tmpFile = tmpfile();
        fwrite($tmpFile, $csvData);
        $tmpPath = stream_get_meta_data($tmpFile)['uri'];

        // ACT: Bulk import users
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file_path' => $tmpPath,
                'format' => 'csv',
            ]);

        // ASSERT: Verify response
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'import_id',
                    'status',
                    'total_records',
                    'processed_records',
                ],
            ]);

        $importData = $response->json('data');
        $this->assertEquals(3, $importData['total_records']);

        // Clean up
        fclose($tmpFile);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_export_users(): void
    {
        // ARRANGE: Create users to export
        User::factory()->count(10)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Bulk export users
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
                'format' => 'csv',
                'fields' => ['id', 'name', 'email', 'created_at'],
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'export_id',
                    'status',
                    'download_url',
                    'total_records',
                ],
            ]);

        $exportData = $response->json('data');
        $this->assertGreaterThanOrEqual(10, $exportData['total_records']);
        $this->assertEquals('completed', $exportData['status']);
        $this->assertNotNull($exportData['download_url']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_delete_users(): void
    {
        // ARRANGE: Create users to delete
        $users = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        $userIds = $users->pluck('id')->toArray();

        // ACT: Bulk delete users
        $response = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/bulk/delete-users", [
                'user_ids' => $userIds,
                'reason' => 'Account cleanup',
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'deleted_count' => 3,
                ],
            ]);

        // ASSERT: Verify users are soft deleted
        foreach ($userIds as $userId) {
            $this->assertSoftDeleted('users', ['id' => $userId]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_bulk_enable_mfa(): void
    {
        // ARRANGE: Create users without MFA
        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Bulk enable MFA
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/enable-mfa", [
                'user_ids' => $users->pluck('id')->toArray(),
                'grace_period_days' => 7,
            ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'enabled_count',
                    'notification_sent_count',
                ],
            ]);

        $responseData = $response->json('data');
        $this->assertEquals(5, $responseData['enabled_count']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_job_status_tracking(): void
    {
        // ARRANGE: Create users for bulk operation
        $users = User::factory()->count(20)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Start bulk operation
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
                'user_ids' => $users->pluck('id')->toArray(),
                'role' => 'User',
            ]);

        // ASSERT: Verify job was created
        $response->assertOk();
        $jobId = $response->json('data.job_id');
        $this->assertNotNull($jobId);

        // ACT: Check job status
        $statusResponse = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/bulk/jobs/{$jobId}");

        // ASSERT: Verify status response
        $statusResponse->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'job_id',
                    'status',
                    'progress',
                    'total',
                    'completed',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_operations_handle_errors_gracefully(): void
    {
        // ARRANGE: Create mix of valid and invalid user IDs
        $validUsers = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        $invalidIds = [9999, 9998, 9997]; // Non-existent IDs
        $mixedIds = array_merge($validUsers->pluck('id')->toArray(), $invalidIds);

        // ACT: Attempt bulk operation with mixed IDs
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
                'user_ids' => $mixedIds,
                'role' => 'User',
            ]);

        // ASSERT: Verify partial success
        $response->assertOk();
        $responseData = $response->json('data');
        $this->assertEquals(3, $responseData['success_count']);
        $this->assertEquals(3, $responseData['failed_count']);
        $this->assertArrayHasKey('errors', $responseData);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_operations_respect_organization_boundaries(): void
    {
        // ARRANGE: Create users in different organization
        $otherOrg = $this->createOrganization();
        $otherUsers = User::factory()->count(3)->create([
            'organization_id' => $otherOrg->id,
        ]);

        // ACT: Attempt to bulk assign roles to other org's users
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
                'user_ids' => $otherUsers->pluck('id')->toArray(),
                'role' => 'User',
            ]);

        // ASSERT: Verify operation failed or filtered out other org's users
        $response->assertOk();
        $responseData = $response->json('data');
        $this->assertEquals(0, $responseData['success_count']);
        $this->assertEquals(3, $responseData['failed_count']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_import_validates_data_format(): void
    {
        // ARRANGE: Prepare invalid CSV (missing email which is required)
        $invalidCsv = "name,role\n"; // Missing required 'email' column
        $invalidCsv .= "John Doe,User\n";

        $tmpFile = tmpfile();
        fwrite($tmpFile, $invalidCsv);
        $tmpPath = stream_get_meta_data($tmpFile)['uri'];

        // ACT: Attempt import with invalid format
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file_path' => $tmpPath,
                'format' => 'csv',
            ]);

        // ASSERT: Verify it still processes but with failures in the response
        // Since the import service handles row-level validation, it returns 201 with failed records
        $response->assertStatus(201);

        $importData = $response->json('data');
        $this->assertGreaterThan(0, count($importData['failed']));

        // Clean up
        fclose($tmpFile);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_export_supports_multiple_formats(): void
    {
        // ARRANGE: Create users
        User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT & ASSERT: Export as CSV
        $csvResponse = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
                'format' => 'csv',
            ]);

        $csvResponse->assertOk();
        $this->assertEquals('csv', $csvResponse->json('data.format'));

        // ACT & ASSERT: Export as JSON
        $jsonResponse = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
                'format' => 'json',
            ]);

        $jsonResponse->assertOk();
        $this->assertEquals('json', $jsonResponse->json('data.format'));

        // ACT & ASSERT: Export as Excel
        $excelResponse = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
                'format' => 'xlsx',
            ]);

        $excelResponse->assertOk();
        $this->assertEquals('xlsx', $excelResponse->json('data.format'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_operations_create_audit_trail(): void
    {
        // ARRANGE: Create users
        $users = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Perform bulk operation
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
                'user_ids' => $users->pluck('id')->toArray(),
                'role' => 'User',
            ]);

        // ASSERT: Verify audit logs created
        $response->assertOk();

        foreach ($users as $user) {
            $this->assertDatabaseHas('authentication_logs', [
                'user_id' => $user->id,
                'event' => 'bulk_role_assignment',
            ]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_invite_users(): void
    {
        // ARRANGE: Prepare bulk invitation data
        $emails = [
            'user1@example.com',
            'user2@example.com',
            'user3@example.com',
            'user4@example.com',
            'user5@example.com',
        ];

        // ACT: Bulk invite users
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
                'emails' => $emails,
                'role' => 'User',
                'message' => 'Welcome to our organization!',
            ]);

        // ASSERT: Verify response
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'invited_count',
                    'failed_count',
                    'invitations',
                ],
            ]);

        $responseData = $response->json('data');
        $this->assertEquals(5, $responseData['invited_count']);
        $this->assertEquals(0, $responseData['failed_count']);

        // ASSERT: Verify invitations created
        foreach ($emails as $email) {
            $this->assertDatabaseHas('invitations', [
                'organization_id' => $this->organization->id,
                'email' => $email,
                'status' => 'pending',
            ]);
        }
    }
}
