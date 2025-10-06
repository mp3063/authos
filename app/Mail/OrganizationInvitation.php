<?php

namespace App\Mail;

use App\Models\Invitation;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class OrganizationInvitation extends Mailable implements ShouldQueue
{
    use Queueable;
    use SerializesModels;

    public Invitation $invitation;

    /**
     * Create a new message instance.
     */
    public function __construct(Invitation $invitation)
    {
        $this->invitation = $invitation;
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: "You've been invited to join {$this->invitation->organization->name}",
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            markdown: 'emails.organization-invitation',
            with: [
                'invitation' => $this->invitation,
                'acceptUrl' => $this->invitation->getInvitationUrl(),
                'organizationName' => $this->invitation->organization->name,
                'inviterName' => $this->invitation->inviter->name,
                'role' => $this->invitation->role,
                'expiresAt' => $this->invitation->expires_at->format('F j, Y'),
                'customMessage' => $this->getCustomMessage(),
            ]
        );
    }

    /**
     * Get custom message from organization settings if available.
     */
    private function getCustomMessage(): ?string
    {
        $settings = $this->invitation->organization->settings ?? [];

        return $settings['email_templates']['invitation']['custom_message'] ?? null;
    }

    /**
     * Get the attachments for the message.
     *
     * @return array<int, \Illuminate\Mail\Mailables\Attachment>
     */
    public function attachments(): array
    {
        return [];
    }
}
