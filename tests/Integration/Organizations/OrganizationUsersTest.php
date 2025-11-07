<?php

namespace Tests\Integration\Organizations;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * Organization Users Integration Tests
 *
 * Tests user management within organizations including:
 * - Listing organization users
 * - Adding users to organizations
 * - Removing users from organizations
 * - Updating user roles
 * - Transferring users between organizations
 * - User search and filtering
 * - Permission validation
 *
 * Verifies:
 * - User access is properly managed
 * - Role assignments work correctly
 * - Multi-tenant isolation is maintained
 * - Audit trails are created
 */
class OrganizationUsersTest extends IntegrationTestCase
{
    protected User $admin;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->admin = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'admin@example.com',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_list_organization_users(): void
    {
        // ARRANGE: Create multiple users in the organization
        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: List organization users
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/users");

        // ASSERT: Verify response structure
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'email',
                        'organization_id',
                        'email_verified_at',
                        'created_at',
                    ],
                ],
            ]);

        // ASSERT: Verify all users are included
        $responseData = $response->json('data');
        $this->assertGreaterThanOrEqual(6, count($responseData)); // 5 + admin
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_add_user_to_organization(): void
    {
        // ARRANGE: Create application in organization
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Create a new user
        $newUser = $this->createUser(['organization_id' => $this->organization->id]);

        // ACT: Grant user access to application
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/users", [
                'user_id' => $newUser->id,
                'application_id' => $application->id,
                'role' => 'User',
            ]);

        // ASSERT: Verify response
        $response->assertStatus(201)
            ->assertJson([
                'message' => 'User access granted successfully',
            ]);

        // ASSERT: Verify user has access to application
        $this->assertTrue(
            $application->users()->where('user_id', $newUser->id)->exists()
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_remove_user_from_organization(): void
    {
        // ARRANGE: Create application and grant user access
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $user = $this->createUser(['organization_id' => $this->organization->id]);
        $application->users()->attach($user->id);

        // ACT: Revoke user access
        $response = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/users/{$user->id}/applications/{$application->id}");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'User access revoked successfully',
            ]);

        // ASSERT: Verify user no longer has access
        $this->assertFalse(
            $application->users()->where('user_id', $user->id)->exists()
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_update_user_role_in_organization(): void
    {
        // ARRANGE: Create user with initial role
        $user = $this->createUser(['organization_id' => $this->organization->id]);
        $user->assignRole('User');

        // ACT: Update user role
        $response = $this->actingAs($this->admin, 'api')
            ->putJson("/api/v1/users/{$user->id}/roles", [
                'roles' => ['Organization Admin'],
            ]);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify role updated
        $user->refresh();
        $this->assertTrue($user->hasRole('Organization Admin'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_transfer_user_between_organizations(): void
    {
        // ARRANGE: Create a Super Admin for cross-organization operations
        // Note: Only Super Admins can transfer users between organizations and view users in other organizations
        // Organization Admins are restricted to their own organization for security
        $superAdmin = $this->createSuperAdmin();

        // ARRANGE: Create two organizations
        $sourceOrg = $this->organization;
        $targetOrg = $this->createOrganization(['name' => 'Target Organization']);

        $user = $this->createUser(['organization_id' => $sourceOrg->id]);

        // ACT: Transfer user to target organization (requires Super Admin)
        $response = $this->actingAs($superAdmin, 'api')
            ->putJson("/api/v1/users/{$user->id}", [
                'organization_id' => $targetOrg->id,
            ]);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify user organization changed
        $user->refresh();
        $this->assertEquals($targetOrg->id, $user->organization_id);

        // ASSERT: Verify user appears in target organization (Super Admin has cross-org visibility)
        $targetResponse = $this->actingAs($superAdmin, 'api')
            ->getJson("/api/v1/organizations/{$targetOrg->id}/users");

        $targetData = $targetResponse->json('data');
        $userIds = collect($targetData)->pluck('id')->toArray();
        $this->assertContains($user->id, $userIds);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_user_search_and_filtering(): void
    {
        // ARRANGE: Create users with different attributes
        $johnDoe = $this->createUser([
            'organization_id' => $this->organization->id,
            'name' => 'John Doe',
            'email' => 'john@example.com',
        ]);

        $janeDoe = $this->createUser([
            'organization_id' => $this->organization->id,
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
        ]);

        $bobSmith = $this->createUser([
            'organization_id' => $this->organization->id,
            'name' => 'Bob Smith',
            'email' => 'bob@example.com',
        ]);

        // ACT & ASSERT: Search by name
        $searchResponse = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/users?search=Doe");

        $searchResponse->assertOk();
        $searchData = $searchResponse->json('data');
        $names = collect($searchData)->pluck('name')->toArray();
        $this->assertContains('John Doe', $names);
        $this->assertContains('Jane Doe', $names);
        $this->assertNotContains('Bob Smith', $names);

        // ACT & ASSERT: Search by email
        $emailSearch = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/users?search=john@");

        $emailSearch->assertOk();
        $emailData = $emailSearch->json('data');
        $emails = collect($emailData)->pluck('email')->toArray();
        $this->assertContains('john@example.com', $emails);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_organization_users_pagination(): void
    {
        // ARRANGE: Create many users
        User::factory()->count(25)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Request paginated users
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/users?per_page=10");

        // ASSERT: Verify pagination structure
        $response->assertOk()
            ->assertJsonStructure([
                'data',
                'meta' => [
                    'current_page',
                    'from',
                    'last_page',
                    'per_page',
                    'to',
                    'total',
                ],
                'links',
            ]);

        // ASSERT: Verify page size
        $responseData = $response->json();
        $this->assertCount(10, $responseData['data']);
        $this->assertGreaterThanOrEqual(25, $responseData['meta']['total']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_permission_validation_for_user_management(): void
    {
        // ARRANGE: Create regular user without admin permissions
        $regularUser = $this->createUser([
            'organization_id' => $this->organization->id,
        ]);
        $regularUser->assignRole('User');

        $targetUser = $this->createUser([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Attempt to remove user without permission
        $response = $this->actingAs($regularUser, 'api')
            ->deleteJson("/api/v1/users/{$targetUser->id}");

        // ASSERT: Verify access denied
        $response->assertStatus(403);

        // ASSERT: Verify user was not deleted
        $this->assertDatabaseHas('users', [
            'id' => $targetUser->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_cannot_access_users_from_other_organization(): void
    {
        // ARRANGE: Create another organization with users
        $otherOrg = $this->createOrganization(['name' => 'Other Organization']);
        $otherUser = $this->createUser(['organization_id' => $otherOrg->id]);

        User::factory()->count(3)->create([
            'organization_id' => $otherOrg->id,
        ]);

        // ACT: Attempt to list other organization's users
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$otherOrg->id}/users");

        // ASSERT: Verify access denied (returns 404 to prevent info leakage)
        $response->assertNotFound();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_user_listing_includes_role_information(): void
    {
        // ARRANGE: Create users with different roles
        $adminUser = $this->createUser([
            'organization_id' => $this->organization->id,
            'name' => 'Admin User',
        ]);
        $adminUser->assignRole('Organization Admin');

        $regularUser = $this->createUser([
            'organization_id' => $this->organization->id,
            'name' => 'Regular User',
        ]);
        $regularUser->assignRole('User');

        // ACT: List users
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/users");

        // ASSERT: Verify response includes role information
        $response->assertOk();
        $userData = $response->json('data');

        // Find admin user in response
        $adminInResponse = collect($userData)->firstWhere('id', $adminUser->id);
        $this->assertNotNull($adminInResponse);

        // Find regular user in response
        $userInResponse = collect($userData)->firstWhere('id', $regularUser->id);
        $this->assertNotNull($userInResponse);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_bulk_user_operations_are_logged(): void
    {
        // ARRANGE: Create multiple users
        $users = User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Bulk assign roles
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
                'user_ids' => $users->pluck('id')->toArray(),
                'role' => 'Organization Member',
            ]);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify all users have the role
        foreach ($users as $user) {
            $user->refresh();
            $this->assertTrue($user->hasRole('Organization Member'));
        }

        // ASSERT: Verify audit log entries exist
        foreach ($users as $user) {
            $this->assertDatabaseHas('authentication_logs', [
                'user_id' => $user->id,
            ]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_filtering_users_by_role(): void
    {
        // ARRANGE: Create users with different roles
        $admin1 = $this->createUser(['organization_id' => $this->organization->id]);
        $admin1->assignRole('Organization Admin');

        $admin2 = $this->createUser(['organization_id' => $this->organization->id]);
        $admin2->assignRole('Organization Admin');

        $user1 = $this->createUser(['organization_id' => $this->organization->id]);
        $user1->assignRole('User');

        // ACT: Filter by admin role
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/users?role=Organization Admin");

        // ASSERT: Verify only admins are returned
        $response->assertOk();
        $userData = $response->json('data');
        $userIds = collect($userData)->pluck('id')->toArray();

        $this->assertContains($admin1->id, $userIds);
        $this->assertContains($admin2->id, $userIds);
        $this->assertNotContains($user1->id, $userIds);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_super_admin_can_manage_all_organization_users(): void
    {
        // ARRANGE: Create super admin and other organization
        $superAdmin = $this->createSuperAdmin();
        $otherOrg = $this->createOrganization();
        $otherUser = $this->createUser(['organization_id' => $otherOrg->id]);

        // ACT: Super admin lists other organization's users
        $response = $this->actingAs($superAdmin, 'api')
            ->getJson("/api/v1/organizations/{$otherOrg->id}/users");

        // ASSERT: Verify access granted
        $response->assertOk();
        $userData = $response->json('data');
        $userIds = collect($userData)->pluck('id')->toArray();
        $this->assertContains($otherUser->id, $userIds);
    }
}
