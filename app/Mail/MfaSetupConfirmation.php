<?php

namespace App\Mail;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class MfaSetupConfirmation extends Mailable implements ShouldQueue
{
    use Queueable;
    use SerializesModels;

    public function __construct(
        public User $user,
        public array $methods = ['totp'],
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Multi-Factor Authentication Enabled - '.config('app.name'),
        );
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'emails.mfa-setup-confirmation',
            with: [
                'userName' => $this->user->name,
                'methods' => $this->methods,
                'appName' => config('app.name'),
            ],
        );
    }
}
