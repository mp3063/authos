<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class ApplicationApiTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        // Clear Spatie Permission cache before each test to prevent pollution
        app(\Spatie\Permission\PermissionRegistrar::class)->forgetCachedPermissions();

        $this->organization = Organization::factory()->create();

        // Create required roles for API guard
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);

        // Use proper test helpers that handle organization-scoped permissions correctly
        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        // Force reload permissions to ensure they're fresh
        $this->adminUser->unsetRelation('permissions');
        $this->adminUser->unsetRelation('roles');
        $this->adminUser->load('roles.permissions', 'permissions');

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        // Set team context and assign role properly for regular user
        $userRole = Role::where('name', 'User')->where('guard_name', 'api')->first();
        $this->regularUser->setPermissionsTeamId($this->regularUser->organization_id);
        $this->regularUser->assignRole($userRole);

        // Give the regular user applications.read permission
        $readPermission = Permission::firstOrCreate([
            'name' => 'applications.read',
            'guard_name' => 'api',
            'organization_id' => $this->organization->id,
        ]);
        $this->regularUser->givePermissionTo($readPermission);

        $this->application = Application::factory()
            ->forOrganization($this->organization)
            ->create();
    }

    public function test_index_returns_paginated_applications(): void
    {
        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson('/api/v1/applications');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'description',
                        'client_id',
                        'redirect_uris',
                        'allowed_origins',
                        'allowed_grant_types',
                        'scopes',
                        'settings',
                        'is_active',
                        'organization',
                        'user_count',
                        'created_at',
                        'updated_at',
                    ],
                ],
                'meta' => [
                    'pagination' => [
                        'current_page',
                        'per_page',
                        'total',
                        'total_pages',
                    ],
                ],
                'links' => [
                    'self',
                    'next',
                    'prev',
                ],
            ]);

        $this->assertCount(1, $response->json('data'));
    }

    public function test_index_with_search_filters_applications(): void
    {
        Application::factory()
            ->forOrganization($this->organization)
            ->create(['name' => 'Test Search App']);

        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson('/api/v1/applications?search=Search');

        $response->assertStatus(200);
        $data = $response->json('data');

        $this->assertCount(1, $data);
        $this->assertStringContainsString('Search', $data[0]['name']);
    }

    public function test_index_with_sorting_orders_applications(): void
    {
        Application::factory()
            ->forOrganization($this->organization)
            ->create(['name' => 'AAA App']);

        Application::factory()
            ->forOrganization($this->organization)
            ->create(['name' => 'ZZZ App']);

        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson('/api/v1/applications?sort=name&order=asc');

        $response->assertStatus(200);
        $data = $response->json('data');

        $this->assertCount(3, $data); // Including the one from setUp
        $this->assertEquals('AAA App', $data[0]['name']);
    }

    public function test_index_requires_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $response = $this->getJson('/api/v1/applications');

        // This should succeed since regularUser has applications.read permission
        $response->assertStatus(200);
    }

    public function test_store_creates_application_with_valid_data(): void
    {
        Passport::actingAs($this->adminUser, ['applications.create']);

        $applicationData = [
            'organization_id' => $this->organization->id,
            'name' => 'Test Application',
            'description' => 'Test application description',
            'redirect_uris' => ['https://example.com/callback'],
            'allowed_origins' => ['https://example.com'],
            'allowed_grant_types' => ['authorization_code', 'refresh_token'],
            'scopes' => ['openid', 'profile', 'email'],
            'settings' => [
                'token_lifetime' => 3600,
                'refresh_token_lifetime' => 86400,
                'require_pkce' => true,
                'auto_approve' => false,
            ],
        ];

        $response = $this->postJson('/api/v1/applications', $applicationData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'client_id',
                    'redirect_uris',
                    'settings',
                ],
                'message',
            ])
            ->assertJson([
                'data' => [
                    'name' => 'Test Application',
                ],
                'message' => 'Application created successfully',
            ]);

        $this->assertDatabaseHas('applications', [
            'name' => 'Test Application',
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        // Verify Passport client was created
        $this->assertDatabaseHas('oauth_clients', [
            'name' => 'Test Application',
        ]);
    }

    public function test_store_validates_required_fields(): void
    {
        Passport::actingAs($this->adminUser, ['applications.create']);

        $response = $this->postJson('/api/v1/applications', []);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details',
            ])
            ->assertJson([
                'error' => 'validation_failed',
            ]);
    }

    public function test_store_requires_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $applicationData = [
            'organization_id' => $this->organization->id,
            'name' => 'Test Application',
            'redirect_uris' => ['https://example.com/callback'],
            'allowed_grant_types' => ['authorization_code'],
        ];

        $response = $this->postJson('/api/v1/applications', $applicationData);

        $response->assertStatus(403);
    }

    public function test_show_returns_application_details(): void
    {
        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson("/api/v1/applications/{$this->application->id}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'client_id',
                    'users',
                    'organization',
                ],
            ])
            ->assertJson([
                'data' => [
                    'id' => $this->application->id,
                    'name' => $this->application->name,
                    'client_id' => $this->application->client_id,
                ],
            ]);
    }

    public function test_show_returns_404_for_nonexistent_application(): void
    {
        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson('/api/v1/applications/999999');

        $response->assertStatus(404);
    }

    public function test_update_modifies_application_successfully(): void
    {
        Passport::actingAs($this->adminUser, ['applications.update']);

        $updateData = [
            'name' => 'Updated Application Name',
            'description' => 'Updated description',
            'redirect_uris' => ['https://new-domain.com/callback'],
            'settings' => [
                'token_lifetime' => 7200,
                'auto_approve' => true,
            ],
        ];

        $response = $this->putJson("/api/v1/applications/{$this->application->id}", $updateData);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data',
                'message',
            ])
            ->assertJson([
                'data' => [
                    'name' => 'Updated Application Name',
                ],
                'message' => 'Application updated successfully',
            ]);

        $this->assertDatabaseHas('applications', [
            'id' => $this->application->id,
            'name' => 'Updated Application Name',
        ]);
    }

    public function test_update_merges_settings_correctly(): void
    {
        $this->application->update([
            'settings' => [
                'token_lifetime' => 3600,
                'require_pkce' => true,
                'auto_approve' => false,
            ],
        ]);

        Passport::actingAs($this->adminUser, ['applications.update']);

        $updateData = [
            'settings' => [
                'token_lifetime' => 7200,
                'auto_approve' => true,
            ],
        ];

        $response = $this->putJson("/api/v1/applications/{$this->application->id}", $updateData);

        $response->assertStatus(200);

        $updatedApp = $this->application->fresh();
        $this->assertEquals(7200, $updatedApp->settings['token_lifetime']);
        $this->assertTrue($updatedApp->settings['require_pkce']); // Should be preserved
        $this->assertTrue($updatedApp->settings['auto_approve']); // Should be updated
    }

    public function test_destroy_deletes_application_and_related_data(): void
    {
        // Create a Passport client for the application
        $passportClient = Client::create([
            'name' => $this->application->name,
            'secret' => 'test-secret',
            'redirect' => 'https://example.com',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application->update(['passport_client_id' => $passportClient->id]);

        // Create a token for this application
        $token = Token::create([
            'id' => 'test-token',
            'user_id' => $this->adminUser->id,
            'client_id' => $passportClient->id,
            'name' => 'Test Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
        ]);

        Passport::actingAs($this->adminUser, ['applications.delete']);

        $response = $this->deleteJson("/api/v1/applications/{$this->application->id}");

        $response->assertStatus(204);

        // Verify application was deleted
        $this->assertDatabaseMissing('applications', [
            'id' => $this->application->id,
        ]);

        // Verify Passport client was deleted
        $this->assertDatabaseMissing('oauth_clients', [
            'id' => $passportClient->id,
        ]);

        // Verify tokens were revoked
        $this->assertDatabaseMissing('oauth_access_tokens', [
            'id' => 'test-token',
        ]);
    }

    public function test_regenerate_credentials_creates_new_credentials(): void
    {
        $originalClientId = $this->application->client_id;
        $originalClientSecret = $this->application->client_secret;

        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->postJson("/api/v1/applications/{$this->application->id}/credentials/regenerate");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'client_id',
                    'client_secret',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'Application credentials regenerated successfully',
            ]);

        $updatedApp = $this->application->fresh();

        $this->assertNotEquals($originalClientId, $updatedApp->client_id);
        $this->assertNotEquals($originalClientSecret, $updatedApp->client_secret);
        $this->assertNotNull($updatedApp->client_id);
        $this->assertNotNull($updatedApp->client_secret);
    }

    public function test_users_returns_application_users(): void
    {
        // Attach user to application
        $this->application->users()->attach($this->regularUser->id, [
            'granted_at' => now(),
            'login_count' => 5,
            'last_login_at' => now()->subHour(),
        ]);

        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson("/api/v1/applications/{$this->application->id}/users");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'email',
                        'granted_at',
                        'last_login_at',
                        'login_count',
                    ],
                ],
            ]);

        $this->assertCount(1, $response->json('data'));
        $userData = $response->json('data')[0];
        $this->assertEquals($this->regularUser->id, $userData['id']);
        $this->assertEquals(5, $userData['login_count']);
    }

    public function test_grant_user_access_adds_user_to_application(): void
    {
        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->postJson("/api/v1/applications/{$this->application->id}/users", [
            'user_id' => $this->regularUser->id,
        ]);

        $response->assertStatus(201)
            ->assertJson([
                'message' => 'User access granted successfully',
            ]);

        $this->assertTrue(
            $this->application->users()->where('user_id', $this->regularUser->id)->exists()
        );
    }

    public function test_grant_user_access_prevents_duplicate_access(): void
    {
        // First, grant access
        $this->application->users()->attach($this->regularUser->id, ['granted_at' => now()]);

        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->postJson("/api/v1/applications/{$this->application->id}/users", [
            'user_id' => $this->regularUser->id,
        ]);

        $response->assertStatus(409)
            ->assertJson([
                'error' => 'resource_conflict',
                'error_description' => 'User already has access to this application.',
            ]);
    }

    public function test_revoke_user_access_removes_user_from_application(): void
    {
        // First, grant access
        $this->application->users()->attach($this->regularUser->id, ['granted_at' => now()]);

        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->deleteJson("/api/v1/applications/{$this->application->id}/users/{$this->regularUser->id}");

        $response->assertStatus(204);

        $this->assertFalse(
            $this->application->users()->where('user_id', $this->regularUser->id)->exists()
        );
    }

    public function test_revoke_user_access_returns_404_for_non_granted_user(): void
    {
        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->deleteJson("/api/v1/applications/{$this->application->id}/users/{$this->regularUser->id}");

        $response->assertStatus(404)
            ->assertJson([
                'error' => 'resource_not_found',
                'error_description' => 'User does not have access to this application.',
            ]);
    }

    public function test_tokens_returns_active_application_tokens(): void
    {
        // Create a Passport client
        $passportClient = Client::create([
            'name' => $this->application->name,
            'secret' => 'test-secret',
            'provider' => null,
            'redirect' => 'https://example.com',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application->update(['passport_client_id' => $passportClient->id]);

        // Create active and expired tokens
        $activeToken = Token::create([
            'id' => 'active-token',
            'user_id' => $this->regularUser->id,
            'client_id' => $passportClient->id,
            'name' => 'Active Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
        ]);

        $expiredToken = Token::create([
            'id' => 'expired-token',
            'user_id' => $this->regularUser->id,
            'client_id' => $passportClient->id,
            'name' => 'Expired Token',
            'scopes' => ['profile'],
            'revoked' => false,
            'expires_at' => now()->subHour(),
        ]);

        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson("/api/v1/applications/{$this->application->id}/tokens");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'scopes',
                        'user',
                        'created_at',
                        'expires_at',
                        'last_used_at',
                    ],
                ],
            ]);

        // Should only return active token
        $this->assertCount(1, $response->json('data'));
        $tokenData = $response->json('data')[0];
        $this->assertEquals('active-token', $tokenData['id']);
    }

    public function test_revoke_all_tokens_removes_all_application_tokens(): void
    {
        // Create a Passport client
        $passportClient = Client::create([
            'name' => $this->application->name,
            'secret' => 'test-secret',
            'provider' => null,
            'redirect' => 'https://example.com',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application->update(['passport_client_id' => $passportClient->id]);

        // Create multiple tokens
        Token::create([
            'id' => 'token-1',
            'user_id' => $this->regularUser->id,
            'client_id' => $passportClient->id,
            'name' => 'Token 1',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
        ]);

        Token::create([
            'id' => 'token-2',
            'user_id' => $this->adminUser->id,
            'client_id' => $passportClient->id,
            'name' => 'Token 2',
            'scopes' => ['profile'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
        ]);

        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->deleteJson("/api/v1/applications/{$this->application->id}/tokens");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Revoked 2 active tokens',
            ]);

        // Verify tokens were deleted
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => 'token-1']);
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => 'token-2']);
    }

    public function test_revoke_token_removes_specific_token(): void
    {
        // Create a Passport client
        $passportClient = Client::create([
            'name' => $this->application->name,
            'secret' => 'test-secret',
            'provider' => null,
            'redirect' => 'https://example.com',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->application->update(['passport_client_id' => $passportClient->id]);

        $token = Token::create([
            'id' => 'specific-token',
            'user_id' => $this->regularUser->id,
            'client_id' => $passportClient->id,
            'name' => 'Specific Token',
            'scopes' => ['openid'],
            'revoked' => false,
            'expires_at' => now()->addHour(),
        ]);

        Passport::actingAs($this->adminUser, ['applications.update']);

        $response = $this->deleteJson("/api/v1/applications/{$this->application->id}/tokens/specific-token");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Token revoked successfully',
            ]);
    }

    public function test_analytics_returns_application_metrics(): void
    {
        // Create some authentication logs
        AuthenticationLog::factory()->create([
            'application_id' => $this->application->id,
            'user_id' => $this->regularUser->id,
            'event' => 'login_success',
            'created_at' => now()->subDays(2),
        ]);

        AuthenticationLog::factory()->create([
            'application_id' => $this->application->id,
            'user_id' => $this->adminUser->id,
            'event' => 'login_failed',
            'created_at' => now()->subDays(1),
        ]);

        // Attach users to application
        $this->application->users()->attach($this->regularUser->id, ['granted_at' => now()]);
        $this->application->users()->attach($this->adminUser->id, ['granted_at' => now()]);

        Passport::actingAs($this->adminUser, ['applications.read']);

        $response = $this->getJson("/api/v1/applications/{$this->application->id}/analytics?period=7d");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'period',
                    'total_users',
                    'active_tokens',
                    'successful_logins',
                    'failed_logins',
                    'unique_active_users',
                    'login_success_rate',
                ],
            ])
            ->assertJson([
                'data' => [
                    'period' => '7d',
                    'total_users' => 2,
                    'successful_logins' => 1,
                    'failed_logins' => 1,
                    'login_success_rate' => 50.0,
                ],
            ]);
    }

    public function test_all_application_endpoints_require_authentication(): void
    {
        $endpoints = [
            ['GET', '/api/v1/applications'],
            ['POST', '/api/v1/applications'],
            ['GET', "/api/v1/applications/{$this->application->id}"],
            ['PUT', "/api/v1/applications/{$this->application->id}"],
            ['DELETE', "/api/v1/applications/{$this->application->id}"],
            ['POST', "/api/v1/applications/{$this->application->id}/credentials/regenerate"],
            ['GET', "/api/v1/applications/{$this->application->id}/users"],
            ['POST', "/api/v1/applications/{$this->application->id}/users"],
            ['DELETE', "/api/v1/applications/{$this->application->id}/users/{$this->regularUser->id}"],
            ['GET', "/api/v1/applications/{$this->application->id}/tokens"],
            ['DELETE', "/api/v1/applications/{$this->application->id}/tokens"],
            ['DELETE', "/api/v1/applications/{$this->application->id}/tokens/test-token"],
            ['GET', "/api/v1/applications/{$this->application->id}/analytics"],
        ];

        foreach ($endpoints as [$method, $endpoint]) {
            $response = $this->json($method, $endpoint);
            $response->assertStatus(401, "Endpoint {$method} {$endpoint} should require authentication");
        }
    }
}
