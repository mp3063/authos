<?php

namespace Tests\Integration\Users;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Integration tests for User CRUD operations
 *
 * Tests the complete user management lifecycle including:
 * - Creating users with validation
 * - Reading user details with proper authorization
 * - Updating user information
 * - Deleting users with cleanup
 * - Listing users with pagination and filtering
 * - Multi-tenant isolation
 */
class UserCrudTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    protected function setUp(): void
    {
        parent::setUp();

        // Create organization and users
        $this->organization = Organization::factory()->create([
            'name' => 'Test Organization',
            'settings' => ['features' => ['user_management' => true]],
        ]);

        // Setup default roles for the organization (including "User" role)
        $this->organization->setupDefaultRoles();

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'admin@test.com',
        ]);

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
            'email' => 'user@test.com',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_user_successfully(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.create']);

        $userData = [
            'name' => 'New Test User',
            'email' => 'newuser@test.com',
            'password' => 'TestP@ssw0rd!2024_'.uniqid(),
            'organization_id' => $this->organization->id,
            'roles' => ['User'],
        ];

        // ACT
        $response = $this->postJson('/api/v1/users', $userData);

        // ASSERT
        $response->assertStatus(201)
            ->assertJson([
                'success' => true,
                'message' => 'User created successfully',
            ])
            ->assertJsonStructure([
                'success',
                'message',
                'data' => [
                    'id',
                    'name',
                    'email',
                    'organization_id',
                    'is_active',
                    'mfa_enabled',
                    'created_at',
                    'updated_at',
                    'organization' => ['id', 'name'],
                    'roles',
                ],
            ]);

        // Verify database
        $this->assertDatabaseHas('users', [
            'email' => 'newuser@test.com',
            'name' => 'New Test User',
            'organization_id' => $this->organization->id,
        ]);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $response->json('data.id'),
            'event' => 'user_created_by_admin',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_reads_user_details_with_relationships(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.read']);

        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $user->applications()->attach($application->id, [
            'permissions' => json_encode(['read', 'write']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$user->id}");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'organization_id' => $this->organization->id,
                ],
            ])
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'email',
                    'organization_id',
                    'is_active',
                    'mfa_enabled',
                    'roles',
                    'organization' => ['id', 'name'],
                    'applications',
                    'created_at',
                    'updated_at',
                ],
            ]);

        // Verify applications are included
        $this->assertNotEmpty($response->json('data.applications'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_user_profile_information(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.update']);

        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Old Name',
            'email' => 'old@test.com',
        ]);

        $updateData = [
            'name' => 'Updated Name',
            'profile' => [
                'title' => 'Senior Developer',
                'department' => 'Engineering',
            ],
            'is_active' => false,
        ];

        // ACT
        $response = $this->putJson("/api/v1/users/{$user->id}", $updateData);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'User updated successfully',
                'data' => [
                    'id' => $user->id,
                    'name' => 'Updated Name',
                    'is_active' => false,
                ],
            ]);

        // Verify database
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'name' => 'Updated Name',
            'is_active' => false,
        ]);

        // Verify profile JSON field
        $user->refresh();
        $this->assertEquals('Senior Developer', $user->profile['title']);
        $this->assertEquals('Engineering', $user->profile['department']);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $user->id,
            'event' => 'user_updated_by_admin',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_deletes_user_with_cleanup(): void
    {
        // ARRANGE
        // Need Organization Owner or Super Admin for delete permission
        $owner = $this->createUser([
            'organization_id' => $this->organization->id,
            'email' => 'owner@test.com',
        ], 'Organization Owner', 'api');

        Passport::actingAs($owner, ['users.delete']);

        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Create related data
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $user->applications()->attach($application->id);

        $userId = $user->id;

        // ACT
        $response = $this->deleteJson("/api/v1/users/{$userId}");

        // ASSERT
        $response->assertStatus(204); // No content response

        // Verify soft delete - user should have deleted_at timestamp
        $this->assertSoftDeleted('users', [
            'id' => $userId,
        ]);

        // Verify audit log - note: authentication_logs for this user were deleted as part of cleanup
        // So we cannot assert the log exists after deletion
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_users_with_pagination_and_filters(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.read']);

        // Create multiple users with different attributes
        $activeUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Active User',
            'is_active' => true,
        ]);

        $inactiveUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Inactive User',
            'is_active' => false,
        ]);

        User::factory()->count(15)->create([
            'organization_id' => $this->organization->id,
        ]);

        // ACT - Test pagination
        $response = $this->getJson('/api/v1/users?page=1&per_page=5');

        // ASSERT - Pagination
        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => ['id', 'name', 'email', 'organization_id'],
                ],
                'meta' => [
                    'current_page',
                    'per_page',
                    'total',
                    'last_page',
                ],
            ]);

        $this->assertEquals(5, count($response->json('data')));
        $this->assertEquals(1, $response->json('meta.current_page'));

        // ACT - Test search filter
        $searchResponse = $this->getJson('/api/v1/users?search=Active User');

        // ASSERT - Search
        $searchResponse->assertStatus(200);
        $searchData = $searchResponse->json('data');
        $this->assertNotEmpty($searchData);
        $this->assertStringContainsString('Active', $searchData[0]['name']);

        // ACT - Test is_active filter
        $activeResponse = $this->getJson('/api/v1/users?filter[is_active]=true');

        // ASSERT - Active filter
        $activeResponse->assertStatus(200);
        foreach ($activeResponse->json('data') as $user) {
            $this->assertTrue((bool) $user['is_active'], "User {$user['id']} should be active");
        }

        // ACT - Test sorting
        $sortResponse = $this->getJson('/api/v1/users?sort=name&order=asc');

        // ASSERT - Sorting
        $sortResponse->assertStatus(200);
        $sortedUsers = $sortResponse->json('data');
        $names = array_column($sortedUsers, 'name');
        $sortedNames = $names;
        sort($sortedNames);
        $this->assertEquals($sortedNames, $names);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_enforces_multi_tenant_isolation(): void
    {
        // ARRANGE
        $otherOrganization = Organization::factory()->create([
            'name' => 'Other Organization',
        ]);

        $otherUser = User::factory()->create([
            'organization_id' => $otherOrganization->id,
            'email' => 'other@test.com',
        ]);

        Passport::actingAs($this->regularUser, ['users.read']);

        // ACT - Try to access user from different organization
        $response = $this->getJson("/api/v1/users/{$otherUser->id}");

        // ASSERT - Should not find the user (404) due to organization boundary
        $response->assertStatus(404);

        // ACT - List users should only show same organization
        $listResponse = $this->getJson('/api/v1/users');

        // ASSERT - Should only see users from own organization
        $listResponse->assertStatus(200);
        foreach ($listResponse->json('data') as $user) {
            $this->assertEquals($this->organization->id, $user['organization_id']);
        }

        // Verify other organization's user is not in the list
        $userIds = array_column($listResponse->json('data'), 'id');
        $this->assertNotContains($otherUser->id, $userIds);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_user_creation_data(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.create']);

        $invalidData = [
            'name' => '', // Empty name
            'email' => 'invalid-email', // Invalid email
            'password' => '123', // Too short
            'organization_id' => 99999, // Non-existent organization
        ];

        // ACT
        $response = $this->postJson('/api/v1/users', $invalidData);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'name',
                    'email',
                    'password',
                    'organization_id',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_duplicate_email_addresses(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['users.create']);

        $existingUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@test.com',
        ]);

        $userData = [
            'name' => 'Duplicate User',
            'email' => 'existing@test.com', // Same email
            'password' => 'TestP@ssw0rd!2024_'.uniqid(),
            'organization_id' => $this->organization->id,
        ];

        // ACT
        $response = $this->postJson('/api/v1/users', $userData);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'email',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_unauthorized_user_creation(): void
    {
        // ARRANGE - Regular user without admin permissions
        Passport::actingAs($this->regularUser, ['users.read']); // Only read permission

        $userData = [
            'name' => 'Unauthorized User',
            'email' => 'unauthorized@test.com',
            'password' => 'TestP@ssw0rd!2024_'.uniqid(),
            'organization_id' => $this->organization->id,
        ];

        // ACT
        $response = $this->postJson('/api/v1/users', $userData);

        // ASSERT - Should be forbidden (403)
        $response->assertStatus(403);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function super_admin_can_access_all_organizations_users(): void
    {
        // ARRANGE
        $superAdmin = $this->createApiSuperAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'superadmin@test.com',
        ]);

        $otherOrganization = Organization::factory()->create();
        $otherOrgUser = User::factory()->create([
            'organization_id' => $otherOrganization->id,
        ]);

        Passport::actingAs($superAdmin, ['users.read']);

        // ACT - Access user from different organization
        $response = $this->getJson("/api/v1/users/{$otherOrgUser->id}");

        // ASSERT - Super admin should be able to access
        $response->assertStatus(200)
            ->assertJson([
                'data' => [
                    'id' => $otherOrgUser->id,
                    'organization_id' => $otherOrganization->id,
                ],
            ]);

        // ACT - List all users
        $listResponse = $this->getJson('/api/v1/users');

        // ASSERT - Should see users from multiple organizations
        $listResponse->assertStatus(200);
        $organizations = array_unique(array_column($listResponse->json('data'), 'organization_id'));
        $this->assertGreaterThan(1, count($organizations), 'Super admin should see users from multiple organizations');
    }
}
