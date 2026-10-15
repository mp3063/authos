<?php

namespace Tests\Integration\Organizations;

use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\UserRoleService;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Organization Invitations Integration Tests
 *
 * Tests organization invitation management including:
 * - Creating invitations
 * - Resending invitations
 * - Bulk inviting users
 * - Accepting invitations
 * - Declining invitations
 * - Canceling invitations
 * - Listing pending invitations
 * - Invitation expiration handling
 *
 * Verifies:
 * - Invitations are properly created and tracked
 * - Email notifications are sent
 * - Expiration logic works correctly
 * - Multi-tenant isolation is maintained
 */
class OrganizationInvitationsTest extends IntegrationTestCase
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
    public function test_can_create_invitation(): void
    {
        // ARRANGE: Prepare invitation data
        $invitationData = [
            'email' => 'newuser@example.com',
            'role' => 'User',
            'message' => 'Welcome to our organization!',
        ];

        // ACT: Create invitation
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations", $invitationData);

        // ASSERT: Verify response
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'email',
                    'role',
                    'token',
                    'expires_at',
                    'status',
                    'invitation_url',
                ],
            ])
            ->assertJson([
                'data' => [
                    'email' => 'newuser@example.com',
                    'role' => 'User',
                    'status' => 'pending',
                ],
            ]);

        // ASSERT: Verify database record
        $this->assertDatabaseHas('invitations', [
            'organization_id' => $this->organization->id,
            'email' => 'newuser@example.com',
            'role' => 'User',
            'status' => 'pending',
            'inviter_id' => $this->admin->id,
        ]);
    }

    #[Test]
    public function test_can_resend_invitation(): void
    {
        // ARRANGE: Create an invitation
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'user@example.com',
            'status' => 'pending',
            'inviter_id' => $this->admin->id,
        ]);

        $originalToken = $invitation->token;

        // ACT: Resend invitation
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'Invitation resent successfully',
            ]);

        // ASSERT: Verify token was regenerated
        $invitation->refresh();
        $this->assertNotEquals($originalToken, $invitation->token);

        // ASSERT: Verify expiration was extended
        $this->assertTrue($invitation->expires_at->isFuture());
    }

    #[Test]
    public function test_can_bulk_invite_users(): void
    {
        // ARRANGE: Prepare bulk invitation data
        $invitations = [
            ['email' => 'user1@example.com', 'role' => 'User'],
            ['email' => 'user2@example.com', 'role' => 'User'],
            ['email' => 'user3@example.com', 'role' => 'Organization Member'],
            ['email' => 'admin@example.com', 'role' => 'Organization Admin'],
        ];

        // ACT: Bulk invite users
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations/bulk", [
                'invitations' => $invitations,
            ]);

        // ASSERT: Verify response
        $response->assertStatus(201)
            ->assertJsonStructure([
                'data' => [
                    'invited_count',
                    'failed_count',
                    'invitations' => [
                        '*' => [
                            'email',
                            'status',
                        ],
                    ],
                ],
            ]);

        $responseData = $response->json('data');
        $this->assertEquals(4, $responseData['invited_count']);
        $this->assertEquals(0, $responseData['failed_count']);

        // ASSERT: Verify all invitations created
        foreach ($invitations as $invitation) {
            $this->assertDatabaseHas('invitations', [
                'organization_id' => $this->organization->id,
                'email' => $invitation['email'],
                'role' => $invitation['role'],
                'status' => 'pending',
            ]);
        }
    }

    #[Test]
    public function test_can_accept_invitation(): void
    {
        // ARRANGE: Create a pending invitation
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->admin->id,
            'email' => 'newuser@example.com',
            'role' => 'User',
            'status' => 'pending',
            'expires_at' => now()->addDays(7),
        ]);

        // Create user account
        $newUser = $this->createUser([
            'email' => 'newuser@example.com',
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Accept invitation
        $response = $this->actingAs($newUser, 'api')
            ->postJson("/api/v1/invitations/{$invitation->token}/accept");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'Invitation accepted successfully',
            ]);

        // ASSERT: Verify invitation status
        $invitation->refresh();
        $this->assertEquals('accepted', $invitation->status);
        $this->assertNotNull($invitation->accepted_at);
        $this->assertEquals($newUser->id, $invitation->accepted_by);
    }

    #[Test]
    public function test_can_decline_invitation(): void
    {
        // ARRANGE: Create a pending invitation
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'user@example.com',
            'status' => 'pending',
            'expires_at' => now()->addDays(7),
        ]);

        // ACT: Decline invitation
        $response = $this->postJson("/api/v1/invitations/{$invitation->token}/decline", [
            'reason' => 'Not interested at this time',
        ]);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'Invitation declined',
            ]);

        // ASSERT: Verify invitation status
        $invitation->refresh();
        $this->assertEquals('declined', $invitation->status);
        $this->assertNotNull($invitation->declined_at);
        $this->assertEquals('Not interested at this time', $invitation->decline_reason);
    }

    #[Test]
    public function test_can_cancel_invitation(): void
    {
        // ARRANGE: Create a pending invitation
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'user@example.com',
            'status' => 'pending',
            'inviter_id' => $this->admin->id,
        ]);

        // ACT: Cancel invitation
        $response = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'Invitation cancelled successfully',
            ]);

        // ASSERT: Verify invitation status
        $invitation->refresh();
        $this->assertEquals('cancelled', $invitation->status);
        $this->assertNotNull($invitation->cancelled_at);
        $this->assertEquals($this->admin->id, $invitation->cancelled_by);
    }

    #[Test]
    public function test_can_list_pending_invitations(): void
    {
        // ARRANGE: Create various invitations
        Invitation::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
            'status' => 'pending',
            'expires_at' => now()->addDays(7),
        ]);

        Invitation::factory()->count(2)->create([
            'organization_id' => $this->organization->id,
            'status' => 'accepted',
        ]);

        Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'status' => 'expired',
        ]);

        // ACT: List pending invitations
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/invitations?status=pending");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => [
                        'id',
                        'email',
                        'role',
                        'status',
                        'expires_at',
                        'created_at',
                    ],
                ],
            ]);

        // ASSERT: Verify only pending invitations returned
        $invitations = $response->json('data');
        $this->assertCount(3, $invitations);
        foreach ($invitations as $invitation) {
            $this->assertEquals('pending', $invitation['status']);
        }
    }

    #[Test]
    public function test_invitation_expiration_handling(): void
    {
        // ARRANGE: Create expired invitation
        $expiredInvitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'expired@example.com',
            'status' => 'pending',
            'expires_at' => now()->subDays(1),
        ]);

        // Create user trying to accept
        $user = $this->createUser([
            'email' => 'expired@example.com',
            'organization_id' => $this->organization->id,
        ]);

        // ACT: Attempt to accept expired invitation
        $response = $this->actingAs($user, 'api')
            ->postJson("/api/v1/invitations/{$expiredInvitation->token}/accept");

        // ASSERT: Verify rejection
        $response->assertStatus(400)
            ->assertJson([
                'error' => 'Invitation has expired',
            ]);

        // ASSERT: Verify invitation status unchanged
        $expiredInvitation->refresh();
        $this->assertEquals('pending', $expiredInvitation->status);
    }

    #[Test]
    public function test_cannot_accept_already_accepted_invitation(): void
    {
        // ARRANGE: Create and accept invitation
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'status' => 'accepted',
            'accepted_at' => now()->subDay(),
            'accepted_by' => $this->admin->id,
        ]);

        // ACT: Attempt to accept again
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/invitations/{$invitation->token}/accept");

        // ASSERT: Verify rejection
        $response->assertStatus(400)
            ->assertJson([
                'error' => 'Invitation already accepted',
            ]);
    }

    #[Test]
    public function test_invitation_respects_organization_boundary(): void
    {
        // ARRANGE: Create invitation in other organization
        $otherOrg = $this->createOrganization();
        $otherInvitation = Invitation::factory()->create([
            'organization_id' => $otherOrg->id,
            'email' => 'other@example.com',
            'status' => 'pending',
        ]);

        // ACT: Attempt to access other organization's invitation
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/invitations");

        // ASSERT: Verify other org's invitation not listed
        $response->assertOk();
        $invitations = $response->json('data');
        $invitationIds = collect($invitations)->pluck('id')->toArray();
        $this->assertNotContains($otherInvitation->id, $invitationIds);

        // ACT: Attempt to cancel other org's invitation
        $cancelResponse = $this->actingAs($this->admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/invitations/{$otherInvitation->id}");

        // ASSERT: Verify access denied
        $cancelResponse->assertNotFound();
    }

    #[Test]
    public function test_bulk_invite_handles_duplicates(): void
    {
        // ARRANGE: Create existing invitation
        Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@example.com',
            'status' => 'pending',
        ]);

        // Prepare bulk data with duplicate
        $invitations = [
            ['email' => 'existing@example.com', 'role' => 'User'], // Duplicate
            ['email' => 'new@example.com', 'role' => 'User'],
        ];

        // ACT: Attempt bulk invite
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations/bulk", [
                'invitations' => $invitations,
            ]);

        // ASSERT: Verify response handles duplicates
        $response->assertStatus(201);
        $responseData = $response->json('data');

        // Should succeed for new, skip or report duplicate
        $this->assertEquals(1, $responseData['invited_count']);
        $this->assertGreaterThanOrEqual(1, $responseData['failed_count']);
    }

    #[Test]
    public function test_invitation_includes_expiration_countdown(): void
    {
        // ARRANGE: Create invitation expiring in 3 days
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'countdown@example.com',
            'status' => 'pending',
            'expires_at' => now()->addDays(3),
        ]);

        // ACT: Get invitation details
        $response = $this->actingAs($this->admin, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/invitations");

        // ASSERT: Verify expiration information
        $response->assertOk();
        $invitations = $response->json('data');
        $targetInvitation = collect($invitations)->firstWhere('id', $invitation->id);

        $this->assertNotNull($targetInvitation);
        $this->assertArrayHasKey('expires_at', $targetInvitation);

        // Verify expires_at is in the future
        $expiresAt = new \DateTime($targetInvitation['expires_at']);
        $this->assertGreaterThan(new \DateTime, $expiresAt);
    }

    #[Test]
    public function test_resending_invitation_extends_expiration(): void
    {
        // ARRANGE: Create invitation expiring soon
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'expiring@example.com',
            'status' => 'pending',
            'expires_at' => now()->addHours(2), // Expires in 2 hours
        ]);

        $originalExpiry = $invitation->expires_at;

        // ACT: Resend invitation
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend");

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify expiration extended
        $invitation->refresh();
        $this->assertGreaterThan($originalExpiry, $invitation->expires_at);
        $this->assertTrue($invitation->expires_at->isAfter(now()->addDays(6)));
    }

    #[Test]
    public function test_invitation_validation_rejects_invalid_emails(): void
    {
        // ARRANGE: Prepare invalid invitation data
        $invalidData = [
            'email' => 'not-an-email',
            'role' => 'User',
        ];

        // ACT: Attempt to create invitation
        $response = $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations", $invalidData);

        // ASSERT: Verify validation error
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    #[Test]
    public function an_admin_cannot_invite_with_a_role_they_could_not_grant_with_422(): void
    {
        $this->createApiSuperAdmin();

        foreach (['Organization Owner', 'Super Admin', 'Nonexistent Role'] as $index => $role) {
            $response = $this->actingAs($this->admin, 'api')
                ->postJson("/api/v1/organizations/{$this->organization->id}/invitations", [
                    'email' => "invitee{$index}@example.com",
                    'role' => $role,
                ]);

            $response->assertUnprocessable()->assertJsonValidationErrors(['role']);
        }

        $this->assertDatabaseCount('invitations', 0);
    }

    #[Test]
    public function bulk_invite_users_rejects_a_role_the_admin_could_not_grant(): void
    {
        $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
                'emails' => ['invitee@example.com'],
                'role' => 'Organization Owner',
            ]);

        $this->assertDatabaseMissing('invitations', ['email' => 'invitee@example.com']);
    }

    #[Test]
    public function a_member_of_another_organization_cannot_accept_an_invitation_with_400(): void
    {
        $outsider = $this->createApiUser();
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->admin->id,
            'email' => $outsider->email,
            'role' => 'Organization Admin',
        ]);

        $response = $this->actingAs($outsider, 'api')->postJson("/api/v1/invitations/{$invitation->token}/accept");

        $response->assertStatus(400);
        $this->assertSame('pending', $invitation->fresh()->status);
        $this->assertTrue($this->assignedRolesNamed($outsider, 'Organization Admin')->isEmpty());
    }

    #[Test]
    public function accepting_an_invitation_does_not_grant_a_role_beyond_the_inviters_permissions(): void
    {
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->admin->id,
            'email' => $member->email,
            'role' => 'Organization Owner',
        ]);

        $response = $this->actingAs($member, 'api')->postJson("/api/v1/invitations/{$invitation->token}/accept");

        $response->assertStatus(400);
        $this->assertTrue($this->assignedRolesNamed($member, 'Organization Owner')->isEmpty());
    }

    #[Test]
    public function accepting_an_invitation_grants_the_invited_role_of_the_organization(): void
    {
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);
        $memberRole = Role::where('name', 'Organization Member')
            ->where('organization_id', $this->organization->id)
            ->where('guard_name', 'api')
            ->firstOrFail();
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $this->admin->id,
            'email' => $member->email,
            'role' => 'Organization Member',
        ]);

        $this->actingAs($member, 'api')->postJson("/api/v1/invitations/{$invitation->token}/accept")->assertOk();

        $this->assertTrue(app(UserRoleService::class)->assignedRoleIds($member)->contains($memberRole->id));
    }

    #[Test]
    public function it_rejects_accepting_an_invitation_created_by_an_inviter_of_another_organization(): void
    {
        $foreignOwner = $this->createApiOrganizationOwner(['organization_id' => $this->createOrganization()->id]);
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $foreignOwner->id,
            'email' => $member->email,
            'role' => 'Organization Admin',
        ]);

        $this->actingAs($member, 'api')->postJson("/api/v1/invitations/{$invitation->token}/accept")->assertStatus(400);

        $this->assertSame('pending', $invitation->fresh()->status);
        $this->assertTrue($this->assignedRolesNamed($member, 'Organization Admin')->isEmpty());
    }

    #[Test]
    public function it_rejects_bulk_invites_with_custom_roles_exceeding_the_inviter_with_422(): void
    {
        $customRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'permissions' => ['organizations.delete', 'roles.manage'],
            'is_active' => true,
        ]);

        $this->actingAs($this->admin, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
                'invitations' => [['email' => 'invitee@example.com', 'role' => 'Organization Member', 'custom_role_id' => $customRole->id]],
            ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['invitations.0.custom_role_id']);

        $this->assertDatabaseMissing('invitations', ['email' => 'invitee@example.com']);
    }

    #[Test]
    public function it_returns_403_when_a_caller_may_not_cancel_an_invitation(): void
    {
        $invitation = Invitation::factory()->forOrganization($this->organization)->create(['inviter_id' => $this->admin->id]);
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);

        $this->actingAs($member, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}")
            ->assertForbidden();

        $this->assertSame('pending', $invitation->fresh()->status);
    }

    #[Test]
    public function it_returns_403_when_a_caller_may_not_resend_an_invitation(): void
    {
        $invitation = Invitation::factory()->forOrganization($this->organization)->create(['inviter_id' => $this->admin->id]);
        $token = $invitation->token;
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);

        $this->actingAs($member, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend")
            ->assertForbidden();

        $this->assertSame($token, $invitation->fresh()->token);
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_invitation_id_the_same_for_a_caller_without_the_ability(): void
    {
        $foreign = Invitation::factory()->forOrganization($this->createOrganization())->create();
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);
        $base = "/api/v1/organizations/{$this->organization->id}/invitations";
        $this->actingAs($member, 'api');

        $this->postJson("{$base}/{$foreign->id}/resend")->assertForbidden();
        $this->postJson("{$base}/999999/resend")->assertForbidden();
        $this->deleteJson("{$base}/{$foreign->id}")->assertForbidden();
        $this->deleteJson("{$base}/999999")->assertForbidden();
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_invitation_id_the_same_for_a_caller_with_the_ability(): void
    {
        $foreign = Invitation::factory()->forOrganization($this->createOrganization())->create();
        $base = "/api/v1/organizations/{$this->organization->id}/invitations";
        $this->actingAs($this->admin, 'api');

        $unknownResend = $this->postJson("{$base}/999999/resend");
        $foreignResend = $this->postJson("{$base}/{$foreign->id}/resend");
        $unknownCancel = $this->deleteJson("{$base}/999999");
        $foreignCancel = $this->deleteJson("{$base}/{$foreign->id}");

        $this->assertSame($unknownResend->status(), $foreignResend->status());
        $this->assertSame($unknownCancel->status(), $foreignCancel->status());
        $this->assertSame('pending', $foreign->fresh()->status);
    }

    #[Test]
    public function it_does_not_act_on_an_invitation_through_another_organizations_url(): void
    {
        $other = $this->createOrganization();
        $otherAdmin = $this->createApiOrganizationAdmin(['organization_id' => $other->id]);
        $invitation = Invitation::factory()->forOrganization($this->organization)->create();

        $this->actingAs($otherAdmin, 'api')
            ->deleteJson("/api/v1/organizations/{$other->id}/invitations/{$invitation->id}")
            ->assertNotFound();
        $this->assertSame('pending', $invitation->fresh()->status);

        $superAdmin = $this->createApiSuperAdmin(['organization_id' => null]);
        $this->actingAs($superAdmin, 'api')
            ->deleteJson("/api/v1/organizations/{$other->id}/invitations/{$invitation->id}")
            ->assertNotFound();
        $this->assertSame('pending', $invitation->fresh()->status);
    }

    #[Test]
    public function it_lets_a_super_admin_without_an_organization_resend_and_cancel_any_invitation(): void
    {
        $superAdmin = $this->createApiSuperAdmin(['organization_id' => null]);
        $invitation = Invitation::factory()->forOrganization($this->organization)->create();
        $base = "/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}";
        $this->actingAs($superAdmin, 'api');

        $this->postJson("{$base}/resend")->assertOk();
        $this->deleteJson($base)->assertOk();
        $this->assertSame('cancelled', $invitation->fresh()->status);
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_organization_the_same_when_listing_invitations(): void
    {
        $foreign = $this->createOrganization();
        $member = $this->createApiUser(['organization_id' => $this->organization->id]);
        $this->actingAs($member, 'api');

        $unknown = $this->getJson('/api/v1/organizations/999999/invitations');
        $foreignResponse = $this->getJson("/api/v1/organizations/{$foreign->id}/invitations");

        $this->assertSame($unknown->status(), $foreignResponse->status());
        $this->assertSame($unknown->json(), $foreignResponse->json());
    }
}
