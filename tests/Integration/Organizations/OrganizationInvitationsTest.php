<?php

namespace Tests\Integration\Organizations;

use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Notification;
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

    #[\PHPUnit\Framework\Attributes\Test]
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

        // ASSERT: Verify notification was sent
        Notification::assertSentTo(
            [$this->admin],
            function ($notification) {
                return true; // Notification system is faked, just verify it was called
            }
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_accept_invitation(): void
    {
        // ARRANGE: Create a pending invitation
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'newuser@example.com',
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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
        $this->assertGreaterThan(new \DateTime(), $expiresAt);
    }

    #[\PHPUnit\Framework\Attributes\Test]
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

    #[\PHPUnit\Framework\Attributes\Test]
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
}
