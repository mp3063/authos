<?php

namespace App\Notifications;

use App\Models\SecurityIncident;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SecurityIncidentAlert extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        public SecurityIncident $incident
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $message = (new MailMessage)
            ->subject("[{$this->incident->severity}] Security Incident - ".config('app.name'));

        if (in_array($this->incident->severity, ['critical', 'high'])) {
            $message->error();
        }

        return $message
            ->greeting('Security Alert')
            ->line("A **{$this->incident->severity}** severity security incident has been detected.")
            ->line("Type: {$this->incident->type}")
            ->line("Description: {$this->incident->description}")
            ->line("IP Address: {$this->incident->ip_address}")
            ->line("Detected at: {$this->incident->detected_at->format('F j, Y g:i A T')}")
            ->action('View Security Dashboard', url('/admin'))
            ->salutation('Best regards, '.config('app.name'));
    }

    public function toArray(object $notifiable): array
    {
        return [
            'incident_id' => $this->incident->id,
            'type' => $this->incident->type,
            'severity' => $this->incident->severity,
            'ip_address' => $this->incident->ip_address,
            'description' => $this->incident->description,
            'detected_at' => $this->incident->detected_at?->toISOString(),
        ];
    }
}
