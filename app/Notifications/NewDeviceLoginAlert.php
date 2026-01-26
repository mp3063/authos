<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewDeviceLoginAlert extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public string $ipAddress,
        public string $userAgent,
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('New Device Login Detected - '.config('app.name'))
            ->error()
            ->greeting('Hello '.$notifiable->name.',')
            ->line('A new login to your account was detected from an unrecognized device.')
            ->line('IP Address: '.$this->ipAddress)
            ->line('Device: '.$this->userAgent)
            ->line('Time: '.now()->format('F j, Y g:i A T'))
            ->line('If this was you, you can ignore this email. If you did not log in, please change your password immediately.')
            ->action('Review Account Security', url('/profile/security'))
            ->salutation('Best regards, '.config('app.name'));
    }

    public function toArray(object $notifiable): array
    {
        return [
            'message' => 'New device login detected',
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'detected_at' => now()->toISOString(),
        ];
    }
}
