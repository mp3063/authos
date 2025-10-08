<?php

namespace App\Notifications;

use App\Models\AccountLockout;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountUnlockedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        public AccountLockout $lockout
    ) {
        //
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $unlockMethod = $this->lockout->unlock_method ?? 'automatic';

        return (new MailMessage)
            ->subject('Account Unlocked')
            ->success()
            ->line('Your account has been unlocked and you can now access your account.')
            ->line("Unlock Method: {$unlockMethod}")
            ->when($this->lockout->unlocked_at, function ($message) {
                return $message->line("Unlocked At: {$this->lockout->unlocked_at->format('Y-m-d H:i:s')}");
            })
            ->line('If you did not expect this notification, please contact support immediately.')
            ->action('Login to Your Account', url('/login'))
            ->line('Thank you for using our service!');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'lockout_id' => $this->lockout->id,
            'unlock_method' => $this->lockout->unlock_method,
            'unlocked_at' => $this->lockout->unlocked_at,
            'original_lockout_type' => $this->lockout->lockout_type,
            'original_reason' => $this->lockout->reason,
        ];
    }
}
