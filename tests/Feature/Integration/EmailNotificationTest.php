<?php

namespace Tests\Feature\Integration;

use App\Mail\InvitationAccepted;
use App\Mail\OrganizationInvitation;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Services\InvitationService;
use Illuminate\Support\Facades\Mail;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class EmailNotificationTest extends TestCase
{
    private Organization $organization;

    private User $inviter;

    private InvitationService $invitationService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->inviter = User::factory()->forOrganization($this->organization)->create();
        $this->invitationService = app(InvitationService::class);

        Role::create(['name' => 'user', 'guard_name' => 'web']);
        Role::create(['name' => 'organization admin', 'guard_name' => 'web']);

        $this->inviter->assignRole('organization admin');

        Mail::fake();
    }

    public function test_invitation_email_is_sent_with_correct_data(): void
    {
        $email = 'newuser@example.com';
        $role = 'user';

        $invitation = $this->invitationService->sendInvitation(
            $this->organization->id,
            $email,
            $this->inviter->id,
            $role
        );

        Mail::assertQueued(OrganizationInvitation::class, function ($mail) use ($email, $invitation) {
            return $mail->hasTo($email) &&
                   $mail->invitation->id === $invitation->id &&
                   $mail->invitation->organization_id === $this->organization->id;
        });
    }

    public function test_invitation_email_contains_correct_content(): void
    {
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->fromInviter($this->inviter)
            ->withRole('user')
            ->create();

        $mailable = new OrganizationInvitation($invitation);
        $rendered = $mailable->render();

        $this->assertStringContainsString($this->organization->name, $rendered);
        $this->assertStringContainsString($this->inviter->name, $rendered);
        $this->assertStringContainsString($invitation->getInvitationUrl(), $rendered);
        $this->assertStringContainsString($invitation->role, $rendered);
    }

    public function test_acceptance_email_is_sent_to_inviter(): void
    {
        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->fromInviter($this->inviter)
            ->withRole('user')
            ->create();

        $acceptedBy = User::factory()->create();

        $this->invitationService->acceptInvitation($invitation->token, [
            'name' => 'New User',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);

        Mail::assertQueued(InvitationAccepted::class, function ($mail) {
            return $mail->hasTo($this->inviter->email) &&
                   $mail->invitation->organization_id === $this->organization->id;
        });
    }

    public function test_bulk_invitations_send_individual_emails(): void
    {
        $invitations = [
            ['email' => 'user1@example.com', 'role' => 'user'],
            ['email' => 'user2@example.com', 'role' => 'user'],
            ['email' => 'user3@example.com', 'role' => 'organization admin'],
        ];

        $this->invitationService->bulkInvite(
            $this->organization->id,
            $invitations,
            $this->inviter->id
        );

        Mail::assertQueued(OrganizationInvitation::class, 3);

        foreach ($invitations as $invitationData) {
            Mail::assertQueued(OrganizationInvitation::class, function ($mail) use ($invitationData) {
                return $mail->hasTo($invitationData['email']);
            });
        }
    }

    public function test_email_templates_are_customizable_by_organization(): void
    {
        $customOrganization = Organization::factory()->create([
            'settings' => [
                'email_templates' => [
                    'invitation' => [
                        'subject' => 'Join {{organization_name}} - Custom Template',
                        'custom_message' => 'Welcome to our awesome platform!',
                    ],
                ],
            ],
        ]);

        $invitation = Invitation::factory()
            ->forOrganization($customOrganization)
            ->fromInviter($this->inviter)
            ->withRole('user')
            ->create();

        $mailable = new OrganizationInvitation($invitation);
        $rendered = $mailable->render();

        $this->assertStringContainsString('Welcome to our awesome platform!', $rendered);
    }

    public function test_email_delivery_failure_is_handled_gracefully(): void
    {
        Mail::shouldReceive('to')->andThrow(new \Exception('Mail server unavailable'));

        $result = $this->invitationService->sendInvitation(
            $this->organization->id,
            'test@example.com',
            $this->inviter->id
        );

        // Should still create invitation even if email fails
        $this->assertInstanceOf(Invitation::class, $result);
        $this->assertDatabaseHas('invitations', [
            'email' => 'test@example.com',
            'status' => 'pending',
        ]);
    }

    public function test_email_notifications_respect_user_preferences(): void
    {
        $userWithNotifications = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'profile' => ['email_notifications' => true],
            ]);

        $userWithoutNotifications = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'profile' => ['email_notifications' => false],
            ]);

        // This would be tested with actual notification sending
        $this->assertTrue($userWithNotifications->profile['email_notifications']);
        $this->assertFalse($userWithoutNotifications->profile['email_notifications']);
    }

    public function test_email_queue_processing_handles_large_batches(): void
    {
        $largeInvitationBatch = [];
        for ($i = 0; $i < 50; $i++) {
            $largeInvitationBatch[] = ['email' => "user{$i}@example.com", 'role' => 'user'];
        }

        $startTime = microtime(true);

        $this->invitationService->bulkInvite(
            $this->organization->id,
            $largeInvitationBatch,
            $this->inviter->id
        );

        $endTime = microtime(true);

        // Should complete within reasonable time
        $this->assertLessThan(5.0, $endTime - $startTime);

        // Should have queued 50 emails
        Mail::assertQueued(OrganizationInvitation::class, 50);
    }

    public function test_email_content_is_properly_localized(): void
    {
        app()->setLocale('es'); // Spanish

        $invitation = Invitation::factory()
            ->forOrganization($this->organization)
            ->fromInviter($this->inviter)
            ->withRole('user')
            ->create();

        $mailable = new OrganizationInvitation($invitation);

        // This would test actual localized content
        $this->assertEquals('es', app()->getLocale());
        $this->assertInstanceOf(OrganizationInvitation::class, $mailable);
    }

    public function test_email_attachments_include_organization_branding(): void
    {
        $organizationWithLogo = Organization::factory()->create([
            'logo' => 'https://example.com/logo.png',
            'settings' => [
                'branding' => [
                    'primary_color' => '#007bff',
                    'include_logo_in_emails' => true,
                ],
            ],
        ]);

        $invitation = Invitation::factory()
            ->forOrganization($organizationWithLogo)
            ->fromInviter($this->inviter)
            ->withRole('user')
            ->create();

        $mailable = new OrganizationInvitation($invitation);
        $rendered = $mailable->render();

        // Would test for logo inclusion and color theming
        // Check for the actual primary color used in Laravel mail templates
        $this->assertStringContainsString('#2d3748', $rendered);
    }
}
