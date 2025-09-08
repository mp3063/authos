<?php

namespace Tests\Feature\Api;

use App\Models\Application;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class BulkOperationsApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;
    private User $organizationOwner;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->organization = Organization::factory()->create();
        
        // Seed roles and permissions properly
        $this->seedRolesAndPermissions();
        
        $this->organizationOwner = $this->createUser([
            'organization_id' => $this->organization->id
        ], 'Organization Owner', 'api');
        
        Mail::fake();
        Storage::fake('local');
    }

    public function test_bulk_invite_users_sends_multiple_invitations(): void
    {
        // Ensure the user has the correct role and permissions by refreshing from database
        $this->organizationOwner = $this->organizationOwner->fresh();
        
        // CRITICAL: Set the team context before checking permissions
        $this->organizationOwner->setPermissionsTeamId($this->organizationOwner->organization_id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organizationOwner->organization_id);
        
        // Refresh user to ensure roles are loaded
        $this->organizationOwner->refresh();
        $this->organizationOwner->load('roles', 'permissions');
        
        // Use Passport actingAs for API authentication with proper scopes
        Passport::actingAs($this->organizationOwner, ['*']);

        $invitations = [
            ['email' => 'user1@example.com', 'role' => 'user'],
            ['email' => 'user2@example.com', 'role' => 'user'],
            ['email' => 'admin@example.com', 'role' => 'organization admin'],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
            'invitations' => $invitations,
            'message' => 'Welcome to our organization!',
            'expires_in_days' => 7,
        ]);

        // Debug the response
        if ($response->status() !== 200) {
            dump('Response status: ' . $response->status());
            dump('User: ' . $this->organizationOwner->email);
            dump('User organization_id: ' . $this->organizationOwner->organization_id);
            dump('Request organization_id: ' . $this->organization->id);
            dump('User roles (all guards): ' . $this->organizationOwner->roles->pluck('name'));
            dump('User roles (api): ' . $this->organizationOwner->getRoleNames('api'));
            dump('User permissions (api): ' . $this->organizationOwner->getAllPermissions('api')->pluck('name'));
        } else {
            // Debug successful response structure
            dump('Response status: ' . $response->status());
            dump('Response JSON: ' . json_encode($response->json(), JSON_PRETTY_PRINT));
        }

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'successful' => [
                        '*' => [
                            'email',
                            'invitation_id',
                            'expires_at',
                        ]
                    ],
                    'failed' => [],
                    'already_exists' => []
                ]
            ])
            ->assertJson([
                'message' => 'Bulk invitation completed: 3 successful, 0 failed, 0 already exist'
            ]);

        // Verify invitations were created
        $this->assertDatabaseCount('invitations', 3);
        foreach ($invitations as $invitation) {
            $this->assertDatabaseHas('invitations', [
                'email' => $invitation['email'],
                'role' => $invitation['role'],
                'organization_id' => $this->organization->id,
                'status' => 'pending',
            ]);
        }
    }

    public function test_bulk_invite_users_handles_duplicate_emails(): void
    {
        // Create existing user
        $existingUser = User::factory()
            ->forOrganization($this->organization)
            ->create(['email' => 'existing@example.com']);

        Passport::actingAs($this->organizationOwner, ['*']);

        $invitations = [
            ['email' => 'new@example.com', 'role' => 'user'],
            ['email' => 'existing@example.com', 'role' => 'user'], // Should fail
            ['email' => 'another@example.com', 'role' => 'user'],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
            'invitations' => $invitations,
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Bulk invitation completed: 2 successful, 0 failed, 1 already exist'
            ]);

        $alreadyExistsResults = $response->json('data.already_exists');
        $this->assertCount(1, $alreadyExistsResults);
        $this->assertEquals('existing@example.com', $alreadyExistsResults[0]['email']);
        $this->assertStringContainsString('already exists', $alreadyExistsResults[0]['reason']);
    }

    public function test_bulk_invite_users_enforces_maximum_batch_size(): void
    {
        Passport::actingAs($this->organizationOwner, ['*']);

        $invitations = [];
        for ($i = 0; $i < 101; $i++) {
            $invitations[] = ['email' => "user{$i}@example.com", 'role' => 'user'];
        }

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
            'invitations' => $invitations,
        ]);

        $response->assertStatus(422)
            ->assertJsonPath('details.invitations.0', 'The invitations field must not have more than 100 items.');
    }

    public function test_bulk_assign_roles_assigns_roles_to_multiple_users(): void
    {
        $users = User::factory()
            ->count(5)
            ->forOrganization($this->organization)
            ->create();

        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        // Set team context for proper role/permission checking
        $this->organizationOwner->setPermissionsTeamId($this->organizationOwner->organization_id);
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organizationOwner->organization_id);
        
        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
            'user_ids' => $users->pluck('id')->toArray(),
            'custom_roles' => [$role->id],  // Fixed: Use correct parameter name
            'action' => 'assign',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'successful' => [],
                    'failed' => []
                ]
            ])
            ->assertJson([
                'message' => 'Bulk role assign completed: 5 successful, 0 failed'
            ]);
            
        // Verify successful count
        $this->assertCount(5, $response->json('data.successful'));

        // Verify all users have the role
        foreach ($users as $user) {
            $this->assertDatabaseHas('user_custom_roles', [
                'user_id' => $user->id,
                'custom_role_id' => $role->id,
            ]);
        }
    }

    public function test_bulk_assign_roles_revokes_roles_from_multiple_users(): void
    {
        $users = User::factory()
            ->count(3)
            ->forOrganization($this->organization)
            ->create();

        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        // Pre-assign roles
        foreach ($users as $user) {
            $role->users()->attach($user->id);
        }

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
            'user_ids' => $users->pluck('id')->toArray(),
            'custom_roles' => [$role->id],
            'action' => 'revoke',
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.successful', function ($successful) {
                return count($successful) === 3;
            });

        // Verify roles were revoked
        foreach ($users as $user) {
            $this->assertDatabaseMissing('user_custom_roles', [
                'user_id' => $user->id,
                'custom_role_id' => $role->id,
            ]);
        }
    }

    public function test_bulk_revoke_access_removes_application_access(): void
    {
        $users = User::factory()
            ->count(4)
            ->forOrganization($this->organization)
            ->create();

        $application = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        // Pre-assign application access
        foreach ($users as $user) {
            $user->applications()->attach($application->id, [
                'permissions' => ['read'],
                'granted_at' => now(),
            ]);
        }

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/revoke-access", [
            'user_ids' => $users->pluck('id')->toArray(),
            'application_ids' => [$application->id],
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'successful',
                    'failed'
                ]
            ])
            ->assertJsonPath('data.successful', function ($successful) {
                return count($successful) === 4;
            });

        // Verify access was revoked
        foreach ($users as $user) {
            $this->assertDatabaseMissing('user_applications', [
                'user_id' => $user->id,
                'application_id' => $application->id,
            ]);
        }
    }

    public function test_bulk_export_users_generates_csv_file(): void
    {
        $application = Application::factory()->forOrganization($this->organization)->create();
        
        $users = User::factory()
            ->count(10)
            ->forOrganization($this->organization)
            ->create();
            
        // Associate users with the application
        foreach ($users as $user) {
            $user->applications()->attach($application->id);
        }

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
            'format' => 'csv',
            'fields' => ['name', 'email', 'created_at', 'is_active'],
            'filters' => [
                'is_active' => true,
            ],
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'download_url',
                    'filename',
                    'users_count',
                    'format',
                    'expires_at',
                ]
            ]);

        $filename = $response->json('data.filename');
        $filePath = 'exports/' . $filename;
        Storage::disk('local')->assertExists($filePath);

        // Verify CSV content
        $csvContent = Storage::disk('local')->get($filePath);
        $this->assertStringContainsString('ID,Name,Email', $csvContent);
        $this->assertStringContainsString($users->first()->email, $csvContent);
    }

    public function test_bulk_export_users_generates_excel_file(): void
    {
        $application = Application::factory()->forOrganization($this->organization)->create();
        
        $users = User::factory()
            ->count(5)
            ->forOrganization($this->organization)
            ->create();
            
        // Associate users with the application
        foreach ($users as $user) {
            $user->applications()->attach($application->id);
        }

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
            'format' => 'xlsx',
            'fields' => ['name', 'email', 'roles'],
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'data' => [
                    'download_url',
                    'filename',
                    'users_count',
                    'format',
                    'expires_at',
                ]
            ]);

        $filename = $response->json('data.filename');
        $filePath = 'exports/' . $filename;
        Storage::disk('local')->assertExists($filePath);
        $this->assertStringContainsString('.xlsx', $filename);
    }

    public function test_bulk_import_users_processes_csv_file(): void
    {
        $csvContent = "name,email,role\n" .
                     "John Doe,john@example.com,user\n" .
                     "Jane Smith,jane@example.com,organization admin\n" .
                     "Bob Wilson,bob@example.com,user";

        $csvFile = UploadedFile::fake()->createWithContent('users.csv', $csvContent);

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
            'file' => $csvFile,
            'send_invitations' => true,
            'invite_expires_in_days' => 14,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'results' => [
                    'processed',
                    'successful',
                    'failed',
                    'invitations_sent',
                ],
                'errors',
            ]);

        // Verify invitations were created
        $this->assertDatabaseHas('invitations', [
            'email' => 'john@example.com',
            'role' => 'user',
            'organization_id' => $this->organization->id,
        ]);

        $this->assertDatabaseHas('invitations', [
            'email' => 'jane@example.com',
            'role' => 'organization admin',
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_bulk_import_users_validates_file_format(): void
    {
        $invalidFile = UploadedFile::fake()->create('users.txt', 100);

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
            'file' => $invalidFile,
        ]);

        $response->assertStatus(422)
            ->assertJsonHas('details.file');
    }

    public function test_bulk_import_users_handles_invalid_data(): void
    {
        $csvContent = "name,email,role\n" .
                     "John Doe,john@example.com,user\n" .
                     ",invalid-email,user\n" .  // Invalid row
                     "Jane Smith,jane@example.com,invalid-role"; // Invalid role

        $csvFile = UploadedFile::fake()->createWithContent('users.csv', $csvContent);

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
            'file' => $csvFile,
            'send_invitations' => true,
        ]);

        $response->assertStatus(200);

        $results = $response->json('results');
        $this->assertEquals(3, $results['processed']);
        $this->assertEquals(1, $results['successful']); // Only John Doe should succeed
        $this->assertEquals(2, $results['failed']);

        // Verify errors are reported
        $errors = $response->json('errors');
        $this->assertCount(2, $errors);
    }

    public function test_bulk_operations_enforce_organization_isolation(): void
    {
        $otherOrganization = Organization::factory()->create();
        $otherUsers = User::factory()
            ->count(3)
            ->forOrganization($otherOrganization)
            ->create();

        Passport::actingAs($this->organizationOwner, ['*']);

        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        // Try to assign role to users from different organization
        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
            'user_ids' => $otherUsers->pluck('id')->toArray(),
            'custom_roles' => [$role->id],
            'action' => 'assign',
        ]);

        $response->assertStatus(422)
            ->assertJsonStructure(['message', 'invalid_users']);

        // Verify no roles were assigned
        foreach ($otherUsers as $user) {
            $this->assertDatabaseMissing('user_custom_roles', [
                'user_id' => $user->id,
                'custom_role_id' => $role->id,
            ]);
        }
    }

    public function test_bulk_operations_require_proper_permissions(): void
    {
        $regularUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($regularUser, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
            'invitations' => [
                ['email' => 'test@example.com', 'role' => 'user']
            ],
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'message' => 'Insufficient permissions',
            ]);
    }

    public function test_bulk_operations_validate_input_data(): void
    {
        Passport::actingAs($this->organizationOwner, ['*']);

        // Test with missing required fields
        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
            'invitations' => [
                ['email' => 'test@example.com'], // Missing role
                ['role' => 'user'], // Missing email
            ],
        ]);

        $response->assertStatus(422)
            ->assertJsonPath('details.invitations.0.role.0', 'The invitations.0.role field is required.')
            ->assertJsonPath('details.invitations.1.email.0', 'The invitations.1.email field is required.');
    }

    public function test_bulk_operations_track_audit_logs(): void
    {
        $users = User::factory()
            ->count(3)
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/revoke-access", [
            'user_ids' => $users->pluck('id')->toArray(),
            'application_id' => Application::factory()->forOrganization($this->organization)->create()->id,
            'reason' => 'Security audit cleanup',
        ]);

        $response->assertStatus(200);

        // Verify audit log entries
        $this->assertDatabaseHas('activity_log', [
            'causer_id' => $this->organizationOwner->id,
            'description' => 'Bulk application access revocation',
        ]);
    }

    public function test_bulk_operations_handle_large_batches_efficiently(): void
    {
        // Create a larger batch to test performance
        $users = User::factory()
            ->count(50)
            ->forOrganization($this->organization)
            ->create();

        $role = CustomRole::factory()
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->organizationOwner, ['*']);

        $startTime = microtime(true);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/assign-roles", [
            'user_ids' => $users->pluck('id')->toArray(),
            'custom_roles' => [$role->id],
            'action' => 'assign',
        ]);

        $endTime = microtime(true);

        $response->assertStatus(200)
            ->assertJsonPath('data.successful', function ($successful) {
                return count($successful) === 50;
            });

        // Should complete within reasonable time (less than 2 seconds)
        $this->assertLessThan(2.0, $endTime - $startTime);
    }

    public function test_bulk_export_handles_large_datasets(): void
    {
        User::factory()
            ->count(1000)
            ->forOrganization($this->organization)
            ->create();

        Passport::actingAs($this->organizationOwner, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/bulk/export-users", [
            'format' => 'csv',
            'fields' => ['name', 'email'],
        ]);

        $response->assertStatus(200);

        $filePath = $response->json('file_path');
        Storage::disk('local')->assertExists($filePath);

        // Verify file is not empty and has reasonable size
        $fileSize = Storage::disk('local')->size($filePath);
        $this->assertGreaterThan(10000, $fileSize); // Should be substantial for 1000 users
    }
}