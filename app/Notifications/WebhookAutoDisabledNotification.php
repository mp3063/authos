<?php

namespace App\Notifications;

use App\Models\Webhook;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class WebhookAutoDisabledNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public Webhook $webhook,
        public string $reason = 'excessive_failures',
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Webhook Auto-Disabled - '.config('app.name'))
            ->error()
            ->greeting('Webhook Alert')
            ->line("A webhook has been automatically disabled due to {$this->reason}.")
            ->line("Webhook: {$this->webhook->name}")
            ->line("URL: {$this->webhook->url}")
            ->line("Failure Count: {$this->webhook->failure_count}")
            ->line('Please review the webhook configuration and re-enable it when the issue is resolved.')
            ->action('Manage Webhooks', url('/admin'))
            ->salutation('Best regards, '.config('app.name'));
    }

    public function toArray(object $notifiable): array
    {
        return [
            'webhook_id' => $this->webhook->id,
            'webhook_name' => $this->webhook->name,
            'webhook_url' => $this->webhook->url,
            'reason' => $this->reason,
            'failure_count' => $this->webhook->failure_count,
            'disabled_at' => now()->toISOString(),
        ];
    }
}
