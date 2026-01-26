<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class PasswordChangedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public string $ipAddress = 'unknown',
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Password Changed - '.config('app.name'))
            ->greeting('Hello '.$notifiable->name.',')
            ->line('Your password was changed successfully.')
            ->line('IP Address: '.$this->ipAddress)
            ->line('If you did not make this change, please contact support immediately and reset your password.')
            ->action('Login to Your Account', url('/login'))
            ->salutation('Best regards, '.config('app.name'));
    }

    public function toArray(object $notifiable): array
    {
        return [
            'message' => 'Password changed successfully',
            'ip_address' => $this->ipAddress,
            'changed_at' => now()->toISOString(),
        ];
    }
}
