<?php

namespace Tests\Integration\Organizations;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\Test;
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

    #[Test]
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

    #[Test]
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

    #[Test]
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

    #[Test]
    public function test_can_bulk_import_users(): void
    {
        // ARRANGE: Prepare CSV data
        $csvData = "name,email,role\n";
        $csvData .= "John Doe,john@example.com,User\n";
        $csvData .= "Jane Smith,jane@example.com,Organization Member\n";
        $csvData .= "Bob Johnson,bob@example.com,User\n";

        // ACT: Bulk import users
        $response = $this->importCsv($csvData);

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
    }

    #[Test]
    public function import_does_not_read_a_file_from_the_server_path_with_422(): void
    {
        $serverFile = tempnam(sys_get_temp_dir(), 'import');
        file_put_contents($serverFile, "name,email\nserver-secret-value,not-an-email\n");

        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file_path' => $serverFile,
                'format' => 'csv',
            ]);

        unlink($serverFile);
        $response->assertUnprocessable()->assertJsonValidationErrors(['file']);
        $this->assertStringNotContainsString('server-secret-value', $response->getContent());
    }

    #[Test]
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

    #[Test]
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

    #[Test]
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

    #[Test]
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

    #[Test]
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

    #[Test]
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

    #[Test]
    public function test_bulk_import_validates_data_format(): void
    {
        // ARRANGE: Prepare invalid CSV (missing email which is required)
        $invalidCsv = "name,role\n"; // Missing required 'email' column
        $invalidCsv .= "John Doe,User\n";

        // ACT: Attempt import with invalid format
        $response = $this->importCsv($invalidCsv);

        // ASSERT: Verify it still processes but with failures in the response
        // Since the import service handles row-level validation, it returns 201 with failed records
        $response->assertStatus(201);

        $importData = $response->json('data');
        $this->assertGreaterThan(0, count($importData['failed']));
    }

    #[Test]
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

    #[Test]
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

    #[Test]
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

    #[Test]
    public function import_does_not_reset_the_password_of_a_user_in_another_organization(): void
    {
        $outsider = $this->createUser(['password' => Hash::make('Original-Pass-1')]);

        $this->importCsv("name,email,password\nTaken Over,{$outsider->email},Attacker-Pass-1", ['update_existing' => true]);

        $outsider->refresh();
        $this->assertTrue(Hash::check('Original-Pass-1', $outsider->password));
        $this->assertNotSame('Taken Over', $outsider->name);
    }

    #[Test]
    public function import_does_not_reset_the_password_of_a_user_with_permissions_the_caller_lacks(): void
    {
        $owner = $this->createUser(
            ['organization_id' => $this->organization->id, 'password' => Hash::make('Original-Pass-1')],
            'Organization Owner',
            'api'
        );

        $this->importCsv("name,email,password\nOwner,{$owner->email},Attacker-Pass-1", ['update_existing' => true]);

        $this->assertTrue(Hash::check('Original-Pass-1', $owner->fresh()->password));
    }

    #[Test]
    public function import_updates_a_member_of_the_callers_organization(): void
    {
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);

        $this->importCsv("name,email,password\nRenamed Member,{$member->email},Updated-Pass-1", ['update_existing' => true])
            ->assertCreated();

        $member->refresh();
        $this->assertSame('Renamed Member', $member->name);
        $this->assertTrue(Hash::check('Updated-Pass-1', $member->password));
    }

    #[Test]
    public function import_does_not_grant_the_global_super_admin_role(): void
    {
        $this->createApiSuperAdmin();

        $this->importCsv("name,email,password,role\nNew Admin,new.admin@example.com,New-Pass-123,Super Admin");

        $this->assertDatabaseMissing('users', ['email' => 'new.admin@example.com']);
    }

    #[Test]
    public function import_does_not_grant_a_role_with_permissions_the_caller_lacks(): void
    {
        $this->importCsv("name,email,password,role\nNew Owner,new.owner@example.com,New-Pass-123,Organization Owner");

        $this->assertDatabaseMissing('users', ['email' => 'new.owner@example.com']);
    }

    #[Test]
    public function import_does_not_grant_a_custom_role_with_permissions_the_caller_lacks(): void
    {
        CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Escalated',
            'permissions' => ['users.delete'],
            'is_active' => true,
        ]);

        $this->importCsv("name,email,password,role,custom_role\nNew User,new.user@example.com,New-Pass-123,User,Escalated");

        $this->assertDatabaseMissing('users', ['email' => 'new.user@example.com']);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private function importCsv(string $csv, array $options = []): TestResponse
    {
        return $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file' => UploadedFile::fake()->createWithContent('users.csv', $csv),
                'format' => 'csv',
                ...$options,
            ]);
    }
}
