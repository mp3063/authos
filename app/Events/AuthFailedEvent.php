<?php

namespace App\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class AuthFailedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public string $email,
        public string $ipAddress,
        public ?int $organizationId = null
    ) {}

    public function getEventType(): string
    {
        return 'auth.failed';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'email' => $this->email,
                'ip_address' => $this->ipAddress,
                'organization_id' => $this->organizationId,
                'timestamp' => now()->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->organizationId,
        ];
    }
}
