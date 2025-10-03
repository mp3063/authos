<?php

namespace Tests\Feature\Api;

use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Services\InvitationService;
use Illuminate\Support\Facades\Mail;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class InvitationApiTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private InvitationService $invitationService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();

        // Create required roles for both guards
        $adminRoleWeb = Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'web']);
        $userRoleWeb = Role::firstOrCreate(['name' => 'User', 'guard_name' => 'web']);
        $adminRoleApi = Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        $userRoleApi = Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);

        // Create admin user with proper permissions
        $this->adminUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        // Set team context and assign role properly - ensure organization_id is correct
        $this->adminUser->organization_id = $this->organization->id;
        $this->adminUser->save();
        $this->adminUser->setPermissionsTeamId($this->adminUser->organization_id);
        $this->adminUser->assignRole($adminRoleApi); // Use API guard for API tests

        // Verify role assignment worked
        $this->assertTrue($this->adminUser->hasRole('Organization Admin'));

        // Create regular user with proper permissions
        $this->regularUser = User::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->regularUser->setPermissionsTeamId($this->regularUser->organization_id);
        $this->regularUser->assignRole($userRoleApi); // Use API guard for API tests

        $this->invitationService = app(InvitationService::class);

        Mail::fake();
    }

    public function test_store_creates_invitation_successfully(): void
    {
        // Set permissions team context before API call
        $this->adminUser->setPermissionsTeamId($this->adminUser->organization_id);

        Passport::actingAs($this->adminUser, ['*']);

        $invitationData = [
            'email' => 'invited@example.com',
            'role' => 'User',
            'metadata' => [
                'department' => 'Engineering',
                'notes' => 'New hire invitation',
            ],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations", $invitationData);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'id',
                    'email',
                    'role',
                    'status',
                    'organization',
                    'inviter',
                    'created_at',
                    'expires_at',
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'email' => 'invited@example.com',
                    'role' => 'User',
                    'status' => 'pending',
                ],
                'message' => 'Invitation sent successfully',
            ]);

        // Verify invitation was created in database
        $this->assertDatabaseHas('invitations', [
            'email' => 'invited@example.com',
            'role' => 'User',
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        // Verify email was queued
        Mail::assertQueued(\App\Mail\OrganizationInvitation::class, function ($mail) {
            return $mail->hasTo('invited@example.com');
        });
    }

    public function test_store_validates_required_fields(): void
    {
        Passport::actingAs($this->adminUser, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations", []);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'success',
                'error',
                'error_description',
                'errors',
            ])
            ->assertJson([
                'success' => false,
                'error' => 'validation_failed',
            ]);
    }

    public function test_store_prevents_duplicate_pending_invitations(): void
    {
        // Create an existing pending invitation
        Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@example.com',
            'role' => 'User',
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        Passport::actingAs($this->adminUser, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations", [
            'email' => 'existing@example.com',
            'role' => 'User',
        ]);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'error' => 'validation_failed',
            ]);
    }

    public function test_index_returns_organization_invitations(): void
    {
        // Create some invitations
        Invitation::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'accepted',
        ]);

        Passport::actingAs($this->adminUser, ['*']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/invitations");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'email',
                        'role',
                        'status',
                        'organization',
                        'inviter',
                        'created_at',
                        'expires_at',
                    ],
                ],
            ])
            ->assertJson([
                'success' => true,
            ]);

        // Should return all invitations (4 total)
        $this->assertCount(4, $response->json('data'));
    }

    public function test_index_filters_by_status(): void
    {
        Invitation::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'accepted',
        ]);

        Passport::actingAs($this->adminUser, ['*']);

        $response = $this->getJson("/api/v1/organizations/{$this->organization->id}/invitations?status=pending");

        $response->assertStatus(200);

        // Should only return pending invitations (2)
        $this->assertCount(2, $response->json('data'));

        foreach ($response->json('data') as $invitation) {
            $this->assertEquals('pending', $invitation['status']);
        }
    }

    public function test_show_returns_invitation_details_for_valid_token(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
            'email' => 'test@example.com',
            'role' => 'User',
        ]);

        $response = $this->getJson("/api/v1/invitations/{$invitation->token}");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'invitation' => [
                    'token',
                    'email',
                    'role',
                    'organization' => [
                        'name',
                        'slug',
                    ],
                    'inviter_name',
                    'expires_at',
                ],
            ])
            ->assertJson([
                'invitation' => [
                    'email' => 'test@example.com',
                    'role' => 'User',
                    'organization' => [
                        'name' => $this->organization->name,
                        'slug' => $this->organization->slug,
                    ],
                    'inviter_name' => $this->adminUser->name,
                ],
            ]);
    }

    public function test_show_returns_404_for_invalid_token(): void
    {
        $response = $this->getJson('/api/v1/invitations/invalid-token');

        $response->assertStatus(404)
            ->assertJson([
                'message' => 'Invitation not found',
            ]);
    }

    public function test_show_returns_error_for_expired_invitation(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'expires_at' => now()->subDays(1), // Expired
            'status' => 'pending',
        ]);

        $response = $this->getJson("/api/v1/invitations/{$invitation->token}");

        $response->assertStatus(400)
            ->assertJsonStructure([
                'message',
                'status',
            ])
            ->assertJson([
                'status' => 'expired',
            ]);
    }

    public function test_show_returns_error_for_already_accepted_invitation(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'accepted',
            'accepted_at' => now(),
        ]);

        $response = $this->getJson("/api/v1/invitations/{$invitation->token}");

        $response->assertStatus(400)
            ->assertJson([
                'status' => 'accepted',
            ]);
    }

    public function test_accept_invitation_successfully(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'email' => $this->regularUser->email,
            'role' => 'User',
            'status' => 'pending',
        ]);

        Passport::actingAs($this->regularUser, ['*']);

        $response = $this->postJson("/api/v1/invitations/{$invitation->token}/accept");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Invitation accepted successfully',
            ]);

        // Verify invitation status was updated
        $this->assertDatabaseHas('invitations', [
            'id' => $invitation->id,
            'status' => 'accepted',
        ]);
    }

    public function test_accept_invitation_requires_authentication(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        $response = $this->postJson("/api/v1/invitations/{$invitation->token}/accept");

        $response->assertStatus(401)
            ->assertJsonStructure([
                'success',
                'error',
                'message',
            ])
            ->assertJson([
                'success' => false,
                'message' => 'Unauthenticated.',
            ]);
    }

    public function test_accept_invitation_fails_for_expired_invitation(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'email' => $this->regularUser->email,
            'expires_at' => now()->subDays(1), // Expired
            'status' => 'pending',
        ]);

        Passport::actingAs($this->regularUser, ['*']);

        $response = $this->postJson("/api/v1/invitations/{$invitation->token}/accept");

        $response->assertStatus(400)
            ->assertJson([
                'message' => 'Failed to accept invitation',
            ]);
    }

    public function test_destroy_cancels_invitation_successfully(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        Passport::actingAs($this->adminUser, ['*']);

        $response = $this->deleteJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}");

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Invitation cancelled successfully',
            ]);

        // Verify invitation status was updated
        $this->assertDatabaseHas('invitations', [
            'id' => $invitation->id,
            'status' => 'cancelled',
        ]);
    }

    public function test_destroy_requires_proper_permissions(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        // Regular user should not be able to cancel invitations
        Passport::actingAs($this->regularUser, ['*']);

        $response = $this->deleteJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}");

        $response->assertStatus(400)
            ->assertJson([
                'message' => 'Failed to cancel invitation',
            ]);
    }

    public function test_resend_invitation_successfully(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
            'email' => 'resend@example.com',
        ]);

        Passport::actingAs($this->adminUser, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'invitation' => [
                    'id',
                    'email',
                    'organization',
                    'inviter',
                ],
            ])
            ->assertJson([
                'message' => 'Invitation resent successfully',
            ]);

        // Verify another email was queued
        Mail::assertQueued(\App\Mail\OrganizationInvitation::class, function ($mail) {
            return $mail->hasTo('resend@example.com');
        });
    }

    public function test_resend_invitation_requires_proper_permissions(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
            'status' => 'pending',
        ]);

        // Regular user should not be able to resend invitations
        Passport::actingAs($this->regularUser, ['*']);

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend");

        $response->assertStatus(400)
            ->assertJson([
                'message' => 'Failed to resend invitation',
            ]);
    }

    public function test_bulk_invite_creates_multiple_invitations(): void
    {
        Passport::actingAs($this->adminUser, ['*']);

        $bulkData = [
            'invitations' => [
                [
                    'email' => 'bulk1@example.com',
                    'role' => 'User',
                    'metadata' => ['department' => 'Engineering'],
                ],
                [
                    'email' => 'bulk2@example.com',
                    'role' => 'User',
                    'metadata' => ['department' => 'Marketing'],
                ],
                [
                    'email' => 'bulk3@example.com',
                    'role' => 'Organization Admin',
                ],
            ],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/bulk", $bulkData);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'results' => [
                    '*' => [
                        'email',
                        'status',
                    ],
                ],
                'summary' => [
                    'total',
                    'successful',
                    'failed',
                ],
            ]);

        $responseData = $response->json();
        $this->assertEquals(3, $responseData['summary']['total']);
        $this->assertStringContainsString('3 sent', $responseData['message']);

        // Verify all invitations were created
        $this->assertDatabaseHas('invitations', ['email' => 'bulk1@example.com']);
        $this->assertDatabaseHas('invitations', ['email' => 'bulk2@example.com']);
        $this->assertDatabaseHas('invitations', ['email' => 'bulk3@example.com']);
    }

    public function test_bulk_invite_validates_invitation_data(): void
    {
        Passport::actingAs($this->adminUser, ['*']);

        $bulkData = [
            'invitations' => [
                [
                    'email' => 'invalid-email', // Invalid email
                    'role' => 'User',
                ],
                [
                    'email' => 'valid@example.com',
                    // Missing role
                ],
            ],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/bulk", $bulkData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['invitations.0.email', 'invitations.1.role']);
    }

    public function test_bulk_invite_handles_partial_failures(): void
    {
        // Create an existing pending invitation to cause one failure
        Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@example.com',
            'status' => 'pending',
        ]);

        Passport::actingAs($this->adminUser, ['*']);

        $bulkData = [
            'invitations' => [
                [
                    'email' => 'new@example.com',
                    'role' => 'User',
                ],
                [
                    'email' => 'existing@example.com', // Should fail due to duplicate
                    'role' => 'User',
                ],
            ],
        ];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/bulk", $bulkData);

        $response->assertStatus(200);

        $responseData = $response->json();
        $this->assertEquals(2, $responseData['summary']['total']);
        $this->assertEquals(1, $responseData['summary']['successful']);
        $this->assertEquals(1, $responseData['summary']['failed']);
    }

    public function test_bulk_invite_respects_maximum_limit(): void
    {
        Passport::actingAs($this->adminUser, ['*']);

        // Create more than the allowed maximum (50)
        $invitations = [];
        for ($i = 1; $i <= 51; $i++) {
            $invitations[] = [
                'email' => "user{$i}@example.com",
                'role' => 'User',
            ];
        }

        $bulkData = ['invitations' => $invitations];

        $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/bulk", $bulkData);

        $response->assertStatus(422)
            ->assertJsonValidationErrors('invitations');
    }

    public function test_all_invitation_endpoints_require_authentication_where_needed(): void
    {
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->adminUser->id,
        ]);

        // These endpoints require authentication
        $protectedEndpoints = [
            ['GET', "/api/v1/organizations/{$this->organization->id}/invitations"],
            ['POST', "/api/v1/organizations/{$this->organization->id}/invitations"],
            ['DELETE', "/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}"],
            ['POST', "/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend"],
            ['POST', "/api/v1/organizations/{$this->organization->id}/invitations/bulk"],
            ['POST', "/api/v1/invitations/{$invitation->token}/accept"], // Requires auth for accepting
        ];

        foreach ($protectedEndpoints as [$method, $endpoint]) {
            $response = $this->json($method, $endpoint);
            $response->assertStatus(401, "Endpoint {$method} {$endpoint} should require authentication");
        }

        // These endpoints are public (don't require auth)
        $publicEndpoints = [
            ['GET', "/api/v1/invitations/{$invitation->token}"],
        ];

        foreach ($publicEndpoints as [$method, $endpoint]) {
            $response = $this->json($method, $endpoint);
            $this->assertNotEquals(401, $response->getStatusCode(), "Endpoint {$method} {$endpoint} should be public");
        }
    }
}
