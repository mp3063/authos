<?php

namespace Tests\Integration\Users;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Integration tests for User-Application Access Management
 *
 * Tests the complete user-application relationship lifecycle including:
 * - Listing user's applications with permissions
 * - Granting application access to users
 * - Revoking application access from users
 * - Viewing application-specific permissions
 * - Bulk grant operations
 * - Bulk revoke operations
 * - Multi-tenant isolation
 */
class UserApplicationsTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create([
            'name' => 'Test Organization',
        ]);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
            'email' => 'admin@test.com',
        ]);

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
            'email' => 'user@test.com',
        ]);

        $this->application = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Test Application',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_users_applications_with_permissions(): void
    {
        // ARRANGE
        Passport::actingAs($this->regularUser, ['applications.read']);

        // Create multiple applications and grant access
        $app1 = Application::factory()->create(['organization_id' => $this->organization->id]);
        $app2 = Application::factory()->create(['organization_id' => $this->organization->id]);
        $app3 = Application::factory()->create(['organization_id' => $this->organization->id]);

        $this->regularUser->applications()->attach($app1->id, [
            'permissions' => json_encode(['read', 'write']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        $this->regularUser->applications()->attach($app2->id, [
            'permissions' => json_encode(['read']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->regularUser->id}/applications");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
            ])
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'client_id',
                        'organization_id',
                        'pivot' => [
                            'permissions',
                            'granted_at',
                            'granted_by',
                            'last_login_at',
                            'login_count',
                        ],
                    ],
                ],
            ]);

        // Should have 2 applications
        $this->assertCount(2, $response->json('data'));

        // Verify permissions are included
        $firstApp = $response->json('data.0');
        $this->assertNotEmpty($firstApp['pivot']['permissions']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_grants_application_access_to_user(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        $permissions = ['read', 'write', 'delete'];

        // ACT
        $response = $this->postJson("/api/v1/users/{$this->regularUser->id}/applications", [
            'application_id' => $this->application->id,
            'permissions' => $permissions,
        ]);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Application access granted successfully',
            ]);

        // Verify database
        $this->assertDatabaseHas('user_applications', [
            'user_id' => $this->regularUser->id,
            'application_id' => $this->application->id,
        ]);

        // Verify permissions were stored correctly
        $pivot = DB::table('user_applications')
            ->where('user_id', $this->regularUser->id)
            ->where('application_id', $this->application->id)
            ->first();

        $storedPermissions = json_decode($pivot->permissions, true);
        $this->assertEquals($permissions, $storedPermissions);
        $this->assertEquals($this->adminUser->id, $pivot->granted_by);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->regularUser->id,
            'event' => 'application_access_granted',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_revokes_application_access_from_user(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        // First grant access
        $this->regularUser->applications()->attach($this->application->id, [
            'permissions' => json_encode(['read', 'write']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        // Verify access was granted
        $this->assertTrue($this->regularUser->applications()->where('application_id', $this->application->id)->exists());

        // ACT
        $response = $this->deleteJson("/api/v1/users/{$this->regularUser->id}/applications/{$this->application->id}");

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Application access revoked successfully',
            ]);

        // Verify database
        $this->assertDatabaseMissing('user_applications', [
            'user_id' => $this->regularUser->id,
            'application_id' => $this->application->id,
        ]);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->regularUser->id,
            'event' => 'application_access_revoked',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_views_application_specific_permissions(): void
    {
        // ARRANGE
        Passport::actingAs($this->regularUser, ['applications.read']);

        $permissions = ['read', 'write', 'admin'];

        $this->regularUser->applications()->attach($this->application->id, [
            'permissions' => json_encode($permissions),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
            'login_count' => 5,
            'last_login_at' => now()->subDay(),
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->regularUser->id}/applications");

        // ASSERT
        $response->assertStatus(200);

        $application = collect($response->json('data'))->firstWhere('id', $this->application->id);
        $this->assertNotNull($application);

        // Verify permissions
        $this->assertEquals($permissions, $application['pivot']['permissions']);

        // Verify metadata
        $this->assertEquals(5, $application['pivot']['login_count']);
        $this->assertNotNull($application['pivot']['last_login_at']);
        $this->assertNotNull($application['pivot']['granted_at']);
        $this->assertEquals($this->adminUser->id, $application['pivot']['granted_by']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_bulk_grants_application_access(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        $userIds = $users->pluck('id')->toArray();
        $permissions = ['read', 'write'];

        // ACT
        $response = $this->postJson("/api/v1/users/{$this->regularUser->id}/applications", [
            'application_id' => $this->application->id,
            'user_ids' => $userIds,
            'permissions' => $permissions,
            'bulk' => true,
        ]);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Application access granted to users successfully',
            ]);

        // Verify all users have access
        foreach ($userIds as $userId) {
            $this->assertDatabaseHas('user_applications', [
                'user_id' => $userId,
                'application_id' => $this->application->id,
            ]);
        }

        // Verify audit logs were created
        foreach ($userIds as $userId) {
            $this->assertDatabaseHas('authentication_logs', [
                'user_id' => $userId,
                'event' => 'application_access_granted',
            ]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_bulk_revokes_application_access(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        $users = User::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
        ]);

        // Grant access to all users
        foreach ($users as $user) {
            $user->applications()->attach($this->application->id, [
                'permissions' => json_encode(['read']),
                'granted_at' => now(),
                'granted_by' => $this->adminUser->id,
            ]);
        }

        $userIds = $users->pluck('id')->toArray();

        // ACT
        $response = $this->deleteJson("/api/v1/users/{$this->regularUser->id}/applications/{$this->application->id}", [
            'user_ids' => $userIds,
            'bulk' => true,
        ]);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Application access revoked from users successfully',
            ]);

        // Verify all users lost access
        foreach ($userIds as $userId) {
            $this->assertDatabaseMissing('user_applications', [
                'user_id' => $userId,
                'application_id' => $this->application->id,
            ]);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_existing_application_permissions(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        // Grant initial access
        $this->regularUser->applications()->attach($this->application->id, [
            'permissions' => json_encode(['read']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        $newPermissions = ['read', 'write', 'admin'];

        // ACT
        $response = $this->postJson("/api/v1/users/{$this->regularUser->id}/applications", [
            'application_id' => $this->application->id,
            'permissions' => $newPermissions,
        ]);

        // ASSERT
        $response->assertStatus(200);

        // Verify permissions were updated
        $pivot = DB::table('user_applications')
            ->where('user_id', $this->regularUser->id)
            ->where('application_id', $this->application->id)
            ->first();

        $storedPermissions = json_decode($pivot->permissions, true);
        $this->assertEquals($newPermissions, $storedPermissions);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_enforces_organization_boundary_for_applications(): void
    {
        // ARRANGE
        $otherOrganization = Organization::factory()->create();
        $otherOrgApp = Application::factory()->create([
            'organization_id' => $otherOrganization->id,
        ]);

        Passport::actingAs($this->adminUser, ['applications.update']);

        // ACT - Try to grant access to application from different organization
        $response = $this->postJson("/api/v1/users/{$this->regularUser->id}/applications", [
            'application_id' => $otherOrgApp->id,
            'permissions' => ['read'],
        ]);

        // ASSERT - Should fail validation or authorization
        $this->assertTrue(in_array($response->status(), [403, 404, 422]));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function regular_user_can_view_own_applications(): void
    {
        // ARRANGE
        Passport::actingAs($this->regularUser, ['applications.read']);

        $this->regularUser->applications()->attach($this->application->id, [
            'permissions' => json_encode(['read']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->regularUser->id}/applications");

        // ASSERT
        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => ['id', 'name', 'pivot'],
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function regular_user_cannot_view_other_users_applications(): void
    {
        // ARRANGE
        $otherUser = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->regularUser, ['applications.read']);

        // ACT
        $response = $this->getJson("/api/v1/users/{$otherUser->id}/applications");

        // ASSERT
        $response->assertStatus(403);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_permissions_format(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        // ACT - Try to grant access with invalid permissions
        $response = $this->postJson("/api/v1/users/{$this->regularUser->id}/applications", [
            'application_id' => $this->application->id,
            'permissions' => 'invalid-not-an-array',
        ]);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['permissions']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_nonexistent_application_gracefully(): void
    {
        // ARRANGE
        Passport::actingAs($this->adminUser, ['applications.update']);

        $nonexistentAppId = 99999;

        // ACT
        $response = $this->postJson("/api/v1/users/{$this->regularUser->id}/applications", [
            'application_id' => $nonexistentAppId,
            'permissions' => ['read'],
        ]);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['application_id']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_login_count_and_last_login(): void
    {
        // ARRANGE
        Passport::actingAs($this->regularUser, ['applications.read']);

        $loginCount = 10;
        $lastLogin = now()->subHours(3);

        $this->regularUser->applications()->attach($this->application->id, [
            'permissions' => json_encode(['read']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
            'login_count' => $loginCount,
            'last_login_at' => $lastLogin,
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->regularUser->id}/applications");

        // ASSERT
        $response->assertStatus(200);

        $application = collect($response->json('data'))->firstWhere('id', $this->application->id);
        $this->assertEquals($loginCount, $application['pivot']['login_count']);
        $this->assertNotNull($application['pivot']['last_login_at']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_applications_with_pagination(): void
    {
        // ARRANGE
        Passport::actingAs($this->regularUser, ['applications.read']);

        // Create and attach many applications
        $applications = Application::factory()->count(15)->create([
            'organization_id' => $this->organization->id,
        ]);

        foreach ($applications as $app) {
            $this->regularUser->applications()->attach($app->id, [
                'permissions' => json_encode(['read']),
                'granted_at' => now(),
                'granted_by' => $this->adminUser->id,
            ]);
        }

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->regularUser->id}/applications?per_page=5&page=1");

        // ASSERT
        $response->assertStatus(200)
            ->assertJsonStructure([
                'data',
                'meta' => [
                    'current_page',
                    'per_page',
                    'total',
                    'last_page',
                ],
            ]);

        $this->assertEquals(5, count($response->json('data')));
        $this->assertEquals(15, $response->json('meta.total'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_filters_applications_by_permission(): void
    {
        // ARRANGE
        Passport::actingAs($this->regularUser, ['applications.read']);

        $app1 = Application::factory()->create(['organization_id' => $this->organization->id]);
        $app2 = Application::factory()->create(['organization_id' => $this->organization->id]);

        $this->regularUser->applications()->attach($app1->id, [
            'permissions' => json_encode(['read', 'write']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        $this->regularUser->applications()->attach($app2->id, [
            'permissions' => json_encode(['read']),
            'granted_at' => now(),
            'granted_by' => $this->adminUser->id,
        ]);

        // ACT
        $response = $this->getJson("/api/v1/users/{$this->regularUser->id}/applications?permission=write");

        // ASSERT
        $response->assertStatus(200);

        // Should only return app1 which has 'write' permission
        $apps = $response->json('data');
        foreach ($apps as $app) {
            $this->assertContains('write', $app['pivot']['permissions']);
        }
    }
}
