<?php

namespace App\Mail;

use App\Models\Invitation;
use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class InvitationAccepted extends Mailable implements ShouldQueue
{
    use Queueable;
    use SerializesModels;

    public Invitation $invitation;

    public User $acceptor;

    /**
     * Create a new message instance.
     */
    public function __construct(Invitation $invitation, User $acceptor)
    {
        $this->invitation = $invitation;
        $this->acceptor = $acceptor;
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: "Invitation accepted by {$this->acceptor->name}",
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            markdown: 'emails.invitation-accepted',
            with: [
                'invitation' => $this->invitation,
                'acceptor' => $this->acceptor,
                'organizationName' => $this->invitation->organization->name,
                'acceptorName' => $this->acceptor->name,
                'acceptorEmail' => $this->acceptor->email,
                'role' => $this->invitation->role,
                'acceptedAt' => $this->invitation->accepted_at->format('F j, Y \a\t g:i A'),
            ]
        );
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
