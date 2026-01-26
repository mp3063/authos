<?php

namespace App\Notifications;

use App\Models\IpBlocklist;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class IpBlockedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public IpBlocklist $block
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $message = (new MailMessage)
            ->subject('IP Address Blocked - '.config('app.name'))
            ->error()
            ->greeting('Security Alert')
            ->line('An IP address has been blocked due to suspicious activity.')
            ->line("IP Address: {$this->block->ip_address}")
            ->line("Block Type: {$this->block->block_type}")
            ->line("Reason: {$this->block->reason}");

        if ($this->block->expires_at) {
            $message->line("Expires: {$this->block->expires_at->format('F j, Y g:i A T')}");
        }

        return $message
            ->action('View Security Dashboard', url('/admin'))
            ->salutation('Best regards, '.config('app.name'));
    }

    public function toArray(object $notifiable): array
    {
        return [
            'ip_address' => $this->block->ip_address,
            'block_type' => $this->block->block_type,
            'reason' => $this->block->reason,
            'blocked_at' => $this->block->blocked_at?->toISOString(),
            'expires_at' => $this->block->expires_at?->toISOString(),
        ];
    }
}
