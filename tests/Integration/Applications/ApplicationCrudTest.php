<?php

namespace Tests\Integration\Applications;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Spatie\Permission\Models\Permission;
use Tests\Integration\IntegrationTestCase;

/**
 * Application CRUD Operations Integration Tests
 *
 * Tests complete CRUD operations for OAuth client applications including:
 * - Creating applications with OAuth credentials
 * - Reading application details
 * - Updating application settings and configurations
 * - Deleting applications and cleaning up tokens
 * - Listing applications with pagination and filtering
 * - Multi-tenant organization isolation
 *
 * @covers \App\Http\Controllers\Api\ApplicationController
 */
class ApplicationCrudTest extends IntegrationTestCase
{
    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        // Create permissions if they don't exist
        Permission::firstOrCreate(['name' => 'applications.create', 'guard_name' => 'api']);
        Permission::firstOrCreate(['name' => 'applications.read', 'guard_name' => 'api']);
        Permission::firstOrCreate(['name' => 'applications.update', 'guard_name' => 'api']);
        Permission::firstOrCreate(['name' => 'applications.delete', 'guard_name' => 'api']);

        $this->organization = $this->createOrganization();
        $this->user = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_oauth_application_with_valid_data(): void
    {
        // ARRANGE: Prepare application data
        $applicationData = [
            'organization_id' => $this->organization->id,
            'name' => 'Test OAuth App',
            'description' => 'Test application for OAuth integration',
            'redirect_uris' => [
                'https://app.example.com/callback',
                'https://localhost:3000/callback',
            ],
            'allowed_origins' => [
                'https://app.example.com',
                'https://localhost:3000',
            ],
            'allowed_grant_types' => ['authorization_code', 'refresh_token'],
            'scopes' => ['openid', 'profile', 'email'],
            'settings' => [
                'token_lifetime' => 3600,
                'refresh_token_lifetime' => 2592000,
                'require_pkce' => true,
                'auto_approve' => false,
            ],
        ];

        // ACT: Create application via API
        $response = $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/applications', $applicationData);

        // ASSERT: Response structure and data
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'description',
                    'client_id',
                    'client_secret',
                    'redirect_uris',
                    'allowed_origins',
                    'allowed_grant_types',
                    'scopes',
                    'settings',
                    'is_active',
                    'organization_id',
                    'organization',
                    'user_count',
                    'created_at',
                    'updated_at',
                ],
                'message',
            ])
            ->assertJson([
                'data' => [
                    'name' => 'Test OAuth App',
                    'description' => 'Test application for OAuth integration',
                    'is_active' => true,
                    'organization_id' => $this->organization->id,
                ],
                'message' => 'Application created successfully',
            ]);

        $responseData = $response->json('data');

        // ASSERT: OAuth credentials generated
        $this->assertNotEmpty($responseData['client_id']);
        $this->assertNotEmpty($responseData['client_secret']);
        $this->assertTrue(Str::isUuid($responseData['client_id']));
        $this->assertEquals(64, strlen($responseData['client_secret']));

        // ASSERT: Database records created
        $this->assertDatabaseHas('applications', [
            'name' => 'Test OAuth App',
            'organization_id' => $this->organization->id,
            'client_id' => $responseData['client_id'],
            'is_active' => true,
        ]);

        // ASSERT: Passport client created
        $application = Application::where('client_id', $responseData['client_id'])->first();
        $this->assertNotNull($application->passport_client_id);
        $this->assertDatabaseHas('oauth_clients', [
            'id' => $application->passport_client_id,
            'name' => 'Test OAuth App',
            'revoked' => false,
        ]);

        // ASSERT: Settings stored correctly
        $this->assertEquals(3600, $application->settings['token_lifetime']);
        $this->assertTrue($application->settings['require_pkce']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_reads_application_details_with_relationships(): void
    {
        // ARRANGE: Create application with users
        $application = $this->createOAuthApplication([
            'name' => 'Test App Details',
            'organization_id' => $this->organization->id,
        ]);

        $user1 = $this->createApiUser(['organization_id' => $this->organization->id]);
        $user2 = $this->createApiUser(['organization_id' => $this->organization->id]);

        $application->users()->attach($user1->id, ['granted_at' => now()]);
        $application->users()->attach($user2->id, ['granted_at' => now()]);

        // ACT: Retrieve application details
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson("/api/v1/applications/{$application->id}");

        // ASSERT: Response structure and data
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'client_id',
                    'client_secret', // Detailed view includes secret
                    'redirect_uris',
                    'allowed_origins',
                    'allowed_grant_types',
                    'scopes',
                    'settings',
                    'is_active',
                    'organization_id',
                    'organization' => ['id', 'name', 'slug'],
                    'user_count',
                    'users' => [
                        '*' => ['id', 'name', 'email', 'granted_at', 'last_login_at', 'login_count'],
                    ],
                    'created_at',
                    'updated_at',
                ],
            ])
            ->assertJson([
                'data' => [
                    'id' => $application->id,
                    'name' => 'Test App Details',
                    'user_count' => 2,
                ],
            ]);

        // ASSERT: Client secret exposed in detailed view
        $this->assertEquals($application->client_secret, $response->json('data.client_secret'));

        // ASSERT: Users included with pivot data
        $users = $response->json('data.users');
        $this->assertCount(2, $users);
        $this->assertNotNull($users[0]['granted_at']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_application_settings_and_configuration(): void
    {
        // ARRANGE: Create application
        $application = $this->createOAuthApplication([
            'name' => 'Original App Name',
            'organization_id' => $this->organization->id,
            'redirect_uris' => ['https://old.example.com/callback'],
            'is_active' => true,
        ]);

        $originalClientId = $application->client_id;
        $originalClientSecret = $application->client_secret;

        // ARRANGE: Prepare update data
        $updateData = [
            'name' => 'Updated App Name',
            'description' => 'Updated description',
            'redirect_uris' => [
                'https://new.example.com/callback',
                'https://another.example.com/callback',
            ],
            'allowed_origins' => ['https://new.example.com'],
            'allowed_grant_types' => ['authorization_code', 'refresh_token', 'client_credentials'],
            'scopes' => ['openid', 'profile', 'email', 'read', 'write'],
            'settings' => [
                'token_lifetime' => 7200,
                'require_pkce' => false,
            ],
            'is_active' => false,
        ];

        // ACT: Update application
        $response = $this->actingAsApiUserWithToken($this->user)
            ->putJson("/api/v1/applications/{$application->id}", $updateData);

        // ASSERT: Response confirms update
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'name' => 'Updated App Name',
                    'description' => 'Updated description',
                    'is_active' => false,
                ],
                'message' => 'Application updated successfully',
            ]);

        // ASSERT: Database updated
        $this->assertDatabaseHas('applications', [
            'id' => $application->id,
            'name' => 'Updated App Name',
            'is_active' => false,
        ]);

        // ASSERT: Credentials unchanged (update doesn't regenerate)
        $application->refresh();
        $this->assertEquals($originalClientId, $application->client_id);
        $this->assertEquals($originalClientSecret, $application->client_secret);

        // ASSERT: Settings merged correctly
        $this->assertEquals(7200, $application->settings['token_lifetime']);
        $this->assertFalse($application->settings['require_pkce']);
        $this->assertEquals('Updated description', $application->settings['description']);

        // ASSERT: Passport client updated
        $passportClient = Client::find($application->passport_client_id);
        $this->assertEquals('Updated App Name', $passportClient->name);
        $this->assertStringContainsString('new.example.com', $passportClient->redirect);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_deletes_application_and_cleans_up_tokens(): void
    {
        // ARRANGE: Create application with active tokens
        $application = $this->createOAuthApplication([
            'organization_id' => $this->organization->id,
        ]);

        $passportClientId = $application->passport_client_id;

        // Create some tokens for this application
        $token1 = $this->createAccessToken($this->user, ['*'], $passportClientId);
        $token2 = $this->createAccessToken($this->user, ['*'], $passportClientId);

        // ACT: Delete application
        $response = $this->actingAsApiUserWithToken($this->user)
            ->deleteJson("/api/v1/applications/{$application->id}");

        // ASSERT: Response confirms deletion
        $response->assertStatus(204)
            ->assertNoContent();

        // ASSERT: Application deleted from database
        $this->assertDatabaseMissing('applications', [
            'id' => $application->id,
        ]);

        // ASSERT: Passport client deleted
        $this->assertDatabaseMissing('oauth_clients', [
            'id' => $passportClientId,
        ]);

        // ASSERT: All tokens revoked/deleted
        $this->assertDatabaseMissing('oauth_access_tokens', [
            'id' => $token1,
        ]);
        $this->assertDatabaseMissing('oauth_access_tokens', [
            'id' => $token2,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_lists_applications_with_pagination_and_filtering(): void
    {
        // ARRANGE: Create multiple applications
        $activeApp1 = $this->createOAuthApplication([
            'name' => 'Active App Alpha',
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        $activeApp2 = $this->createOAuthApplication([
            'name' => 'Active App Beta',
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        $inactiveApp = $this->createOAuthApplication([
            'name' => 'Inactive App Gamma',
            'organization_id' => $this->organization->id,
            'is_active' => false,
        ]);

        // Create application in different organization (should not appear)
        $otherOrg = $this->createOrganization();
        $otherOrgApp = $this->createOAuthApplication([
            'name' => 'Other Org App',
            'organization_id' => $otherOrg->id,
        ]);

        // ACT: List all applications
        $response = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/applications?per_page=10');

        // ASSERT: Only user's organization apps returned
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'name',
                        'client_id',
                        'is_active',
                        'organization',
                        'user_count',
                        'created_at',
                    ],
                ],
                'meta' => ['pagination'],
                'links',
            ]);

        $data = $response->json('data');
        $this->assertCount(3, $data); // Only 3 from user's org
        $this->assertNotContains($otherOrgApp->id, array_column($data, 'id'));

        // ACT: Filter by active status
        $activeResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/applications?is_active=true');

        // ASSERT: Only active applications returned
        $activeData = $activeResponse->json('data');
        $this->assertCount(2, $activeData);
        $this->assertContains($activeApp1->id, array_column($activeData, 'id'));
        $this->assertContains($activeApp2->id, array_column($activeData, 'id'));
        $this->assertNotContains($inactiveApp->id, array_column($activeData, 'id'));

        // ACT: Search by name
        $searchResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/applications?search=Alpha');

        // ASSERT: Search results match
        $searchData = $searchResponse->json('data');
        $this->assertCount(1, $searchData);
        $this->assertEquals('Active App Alpha', $searchData[0]['name']);

        // ACT: Test pagination
        $paginatedResponse = $this->actingAsApiUserWithToken($this->user)
            ->getJson('/api/v1/applications?per_page=2&page=1');

        // ASSERT: Pagination metadata
        $paginatedResponse->assertOk()
            ->assertJsonPath('meta.pagination.per_page', 2)
            ->assertJsonPath('meta.pagination.current_page', 1);

        $this->assertCount(2, $paginatedResponse->json('data'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_enforces_multi_tenant_organization_boundaries(): void
    {
        // ARRANGE: Create applications in different organizations
        $org1 = $this->createOrganization(['name' => 'Organization 1']);
        $org2 = $this->createOrganization(['name' => 'Organization 2']);

        $user1 = $this->createApiUser(['organization_id' => $org1->id]);
        $user2 = $this->createApiUser(['organization_id' => $org2->id]);

        $permissions = Permission::where('guard_name', 'api')
            ->whereIn('name', ['applications.create', 'applications.read', 'applications.update', 'applications.delete'])
            ->get();
        $user1->givePermissionTo($permissions);

        $readPerm = Permission::where('guard_name', 'api')
            ->where('name', 'applications.read')
            ->first();
        $user2->givePermissionTo($readPerm);

        $app1 = $this->createOAuthApplication([
            'name' => 'Org 1 Application',
            'organization_id' => $org1->id,
        ]);

        $app2 = $this->createOAuthApplication([
            'name' => 'Org 2 Application',
            'organization_id' => $org2->id,
        ]);

        // ACT & ASSERT: User 1 can only see their org's applications
        $response1 = $this->actingAsApiUserWithToken($user1)
            ->getJson('/api/v1/applications');

        $response1->assertOk();
        $data1 = $response1->json('data');
        $this->assertCount(1, $data1);
        $this->assertEquals($app1->id, $data1[0]['id']);
        $this->assertNotContains($app2->id, array_column($data1, 'id'));

        // ACT & ASSERT: User 2 cannot access Org 1's application
        $response2 = $this->actingAsApiUserWithToken($user2)
            ->getJson("/api/v1/applications/{$app1->id}");

        // Should return 404 (not 403) to prevent information leakage
        $response2->assertNotFound();

        // ACT & ASSERT: User 1 cannot update Org 2's application
        $updateResponse = $this->actingAsApiUserWithToken($user1)
            ->putJson("/api/v1/applications/{$app2->id}", [
                'name' => 'Hacked Name',
            ]);

        $updateResponse->assertNotFound();

        // ASSERT: Application not modified
        $app2->refresh();
        $this->assertEquals('Org 2 Application', $app2->name);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_redirect_uris_and_required_fields(): void
    {
        // ACT: Attempt to create application without required fields
        $response = $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/applications', [
                // Missing required fields
            ]);

        // ASSERT: Validation errors
        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'organization_id',
                    'name',
                    'redirect_uris',
                    'allowed_grant_types',
                ],
            ])
            ->assertJson([
                'error' => 'validation_failed',
            ]);

        // ACT: Attempt with invalid redirect URIs
        $invalidResponse = $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/applications', [
                'organization_id' => $this->organization->id,
                'name' => 'Test App',
                'redirect_uris' => [
                    'not-a-valid-url',
                    'http://valid.com/callback',
                ],
                'allowed_grant_types' => ['authorization_code'],
            ]);

        // ASSERT: Validation catches invalid URLs
        $invalidResponse->assertStatus(422)
            ->assertJsonPath('details.redirect_uris.0', 'The redirect_uris.0 field must be a valid URL.');

        // ACT: Test too many redirect URIs (max 10)
        $tooManyUris = array_fill(0, 11, 'https://example.com/callback');

        $tooManyResponse = $this->actingAsApiUserWithToken($this->user)
            ->postJson('/api/v1/applications', [
                'organization_id' => $this->organization->id,
                'name' => 'Test App',
                'redirect_uris' => $tooManyUris,
                'allowed_grant_types' => ['authorization_code'],
            ]);

        // ASSERT: Validation enforces maximum
        $tooManyResponse->assertStatus(422)
            ->assertJsonPath('details.redirect_uris.0', 'The redirect_uris field must not have more than 10 items.');
    }
}
