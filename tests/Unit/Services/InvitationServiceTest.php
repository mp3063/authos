<?php

namespace Tests\Unit\Services;

use App\Mail\InvitationAccepted;
use App\Mail\OrganizationInvitation;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Services\InvitationService;
use Exception;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Validation\ValidationException;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class InvitationServiceTest extends TestCase
{
    use RefreshDatabase;

    private InvitationService $invitationService;

    private Organization $organization;

    private User $inviter;

    protected function setUp(): void
    {
        parent::setUp();

        $this->invitationService = app(InvitationService::class);
        $this->organization = Organization::factory()->create();
        $this->inviter = User::factory()->forOrganization($this->organization)->create();

        // Create required roles
        Role::create(['name' => 'user', 'guard_name' => 'web']);
        Role::create(['name' => 'organization admin', 'guard_name' => 'web']);

        // Give inviter permission to invite
        $this->inviter->assignRole('organization admin');

        Mail::fake();
        Queue::fake();
    }

    public function test_send_invitation_creates_invitation_and_sends_email(): void
    {
        $email = 'test@example.com';
        $role = 'user';

        $invitation = $this->invitationService->sendInvitation(
            $this->organization->id,
            $email,
            $this->inviter->id,
            $role
        );

        $this->assertInstanceOf(Invitation::class, $invitation);
        $this->assertEquals($email, $invitation->email);
        $this->assertEquals($role, $invitation->role);
        $this->assertEquals($this->organization->id, $invitation->organization_id);
        $this->assertEquals($this->inviter->id, $invitation->inviter_id);
        $this->assertEquals('pending', $invitation->status);
        $this->assertNotNull($invitation->token);
        $this->assertNotNull($invitation->expires_at);

        Mail::assertQueued(OrganizationInvitation::class, function ($mail) use ($email) {
            return $mail->hasTo($email);
        });
    }

    public function test_send_invitation_throws_exception_when_user_already_in_organization(): void
    {
        $existingUser = User::factory()->forOrganization($this->organization)->create();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('User is already a member of this organization');

        $this->invitationService->sendInvitation(
            $this->organization->id,
            $existingUser->email,
            $this->inviter->id
        );
    }

    public function test_send_invitation_throws_exception_when_inviter_lacks_permission(): void
    {
        $unauthorizedUser = User::factory()->forOrganization($this->organization)->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('User does not have permission to invite users to this organization');

        $this->invitationService->sendInvitation(
            $this->organization->id,
            'test@example.com',
            $unauthorizedUser->id
        );
    }

    public function test_send_invitation_replaces_existing_pending_invitation(): void
    {
        $email = 'test@example.com';

        // Create existing pending invitation
        $existingInvitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->forEmail($email)
            ->create(['status' => 'pending']);

        $newInvitation = $this->invitationService->sendInvitation(
            $this->organization->id,
            $email,
            $this->inviter->id
        );

        $this->assertNotEquals($existingInvitation->id, $newInvitation->id);
        $this->assertDatabaseMissing('invitations', ['id' => $existingInvitation->id]);
        $this->assertDatabaseHas('invitations', ['id' => $newInvitation->id, 'status' => 'pending']);
    }

    public function test_accept_invitation_creates_user_and_assigns_role(): void
    {
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->fromInviter($this->inviter)
            ->withRole('user')
            ->create();

        $userData = [
            'name' => 'John Doe',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ];

        $user = $this->invitationService->acceptInvitation($invitation->token, $userData);

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals($invitation->email, $user->email);
        $this->assertEquals('John Doe', $user->name);
        $this->assertEquals($this->organization->id, $user->organization_id);
        $this->assertTrue($user->hasRole('user'));

        $invitation->refresh();
        $this->assertEquals('accepted', $invitation->status);
        $this->assertEquals($user->id, $invitation->accepted_by);
        $this->assertNotNull($invitation->accepted_at);

        Mail::assertQueued(InvitationAccepted::class);
    }

    public function test_accept_invitation_throws_exception_for_invalid_token(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid or expired invitation');

        $this->invitationService->acceptInvitation('invalid-token', [
            'name' => 'John Doe',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);
    }

    public function test_accept_invitation_throws_exception_for_expired_invitation(): void
    {
        $invitation = Invitation::factory()
            ->expired()
            ->forOrganization($this->organization)
            ->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid or expired invitation');

        $this->invitationService->acceptInvitation($invitation->token, [
            'name' => 'John Doe',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);
    }

    public function test_accept_invitation_throws_exception_for_already_accepted_invitation(): void
    {
        $invitation = Invitation::factory()
            ->accepted()
            ->forOrganization($this->organization)
            ->create();

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invitation has already been accepted');

        $this->invitationService->acceptInvitation($invitation->token, [
            'name' => 'John Doe',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);
    }

    public function test_bulk_invite_sends_multiple_invitations(): void
    {
        $invitations = [
            ['email' => 'user1@example.com', 'role' => 'user'],
            ['email' => 'user2@example.com', 'role' => 'user'],
            ['email' => 'admin@example.com', 'role' => 'organization admin'],
        ];

        $results = $this->invitationService->bulkInvite(
            $this->organization->id,
            $invitations,
            $this->inviter->id
        );

        $this->assertCount(3, $results['successful']);
        $this->assertCount(0, $results['failed']);

        $this->assertDatabaseCount('invitations', 3);

        foreach ($invitations as $invitationData) {
            $this->assertDatabaseHas('invitations', [
                'email' => $invitationData['email'],
                'role' => $invitationData['role'],
                'organization_id' => $this->organization->id,
                'status' => 'pending',
            ]);
        }

        Mail::assertQueued(OrganizationInvitation::class, 3);
    }

    public function test_bulk_invite_handles_mixed_success_and_failure(): void
    {
        // Create existing user to cause failure
        $existingUser = User::factory()->forOrganization($this->organization)->create();

        $invitations = [
            ['email' => 'user1@example.com', 'role' => 'user'], // Should succeed
            ['email' => $existingUser->email, 'role' => 'user'], // Should fail
            ['email' => 'user2@example.com', 'role' => 'user'], // Should succeed
        ];

        $results = $this->invitationService->bulkInvite(
            $this->organization->id,
            $invitations,
            $this->inviter->id
        );

        $this->assertCount(2, $results['successful']);
        $this->assertCount(1, $results['failed']);

        $failedInvitation = $results['failed'][0];
        $this->assertEquals($existingUser->email, $failedInvitation['email']);
        $this->assertStringContainsString('already a member', $failedInvitation['error']);
    }

    public function test_bulk_invite_enforces_maximum_batch_size(): void
    {
        $invitations = [];
        for ($i = 0; $i < 101; $i++) {
            $invitations[] = ['email' => "user{$i}@example.com", 'role' => 'user'];
        }

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Cannot invite more than 100 users at once');

        $this->invitationService->bulkInvite(
            $this->organization->id,
            $invitations,
            $this->inviter->id
        );
    }

    public function test_get_pending_invitations_returns_correct_invitations(): void
    {
        // Create pending invitations for organization
        Invitation::factory()->count(3)
            ->forOrganization($this->organization)
            ->create(['status' => 'pending']);

        // Create invitations for different organization
        $otherOrganization = Organization::factory()->create();
        Invitation::factory()->count(2)
            ->forOrganization($otherOrganization)
            ->create(['status' => 'pending']);

        // Create accepted invitation for same organization
        Invitation::factory()
            ->forOrganization($this->organization)
            ->accepted()
            ->create();

        $pendingInvitations = $this->invitationService->getPendingInvitations($this->organization->id);

        $this->assertCount(3, $pendingInvitations);
        foreach ($pendingInvitations as $invitation) {
            $this->assertEquals('pending', $invitation->status);
            $this->assertEquals($this->organization->id, $invitation->organization_id);
        }
    }

    public function test_cancel_invitation_updates_status_correctly(): void
    {
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->create(['status' => 'pending']);

        $result = $this->invitationService->cancelInvitation($invitation->id, $this->inviter);

        $this->assertTrue($result);

        $invitation->refresh();
        $this->assertEquals('cancelled', $invitation->status);
        $this->assertNotNull($invitation->cancelled_at);
        $this->assertEquals($this->inviter->id, $invitation->cancelled_by);
    }

    public function test_cancel_invitation_throws_exception_for_unauthorized_user(): void
    {
        $unauthorizedUser = User::factory()->create();
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->create(['status' => 'pending']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Not authorized to cancel this invitation');

        $this->invitationService->cancelInvitation($invitation->id, $unauthorizedUser);
    }

    public function test_resend_invitation_creates_new_invitation_and_sends_email(): void
    {
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->create(['status' => 'pending']);

        $originalToken = $invitation->token;
        $originalExpiresAt = $invitation->expires_at;

        // Wait a moment to ensure time difference
        sleep(1);

        $newInvitation = $this->invitationService->resendInvitation($invitation->id, $this->inviter);

        $this->assertNotEquals($originalToken, $newInvitation->token);
        $this->assertGreaterThan($originalExpiresAt, $newInvitation->expires_at);
        $this->assertEquals('pending', $newInvitation->status);

        Mail::assertQueued(OrganizationInvitation::class, function ($mail) use ($invitation) {
            return $mail->hasTo($invitation->email);
        });
    }
}
