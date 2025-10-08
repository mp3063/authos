<?php

namespace App\Notifications;

use App\Models\AccountLockout;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountLockedNotification extends Notification implements ShouldQueue
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
        $unlockTime = $this->lockout->unlock_at
            ? $this->lockout->unlock_at->format('Y-m-d H:i:s')
            : 'N/A';

        return (new MailMessage)
            ->subject('Account Locked - Security Alert')
            ->error()
            ->line('Your account has been temporarily locked due to security concerns.')
            ->line("Reason: {$this->lockout->reason}")
            ->line("Lockout Type: {$this->lockout->lockout_type}")
            ->when($this->lockout->unlock_at, function ($message) use ($unlockTime) {
                return $message->line("Your account will be automatically unlocked at: {$unlockTime}");
            })
            ->line('If you did not attempt to access your account, please contact support immediately.')
            ->action('Contact Support', url('/support'))
            ->line('Thank you for your attention to this matter.');
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
            'lockout_type' => $this->lockout->lockout_type,
            'reason' => $this->lockout->reason,
            'ip_address' => $this->lockout->ip_address,
            'locked_at' => $this->lockout->locked_at,
            'unlock_at' => $this->lockout->unlock_at,
        ];
    }
}
