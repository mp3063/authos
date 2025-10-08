<?php

namespace App\Events;

use App\Models\User;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UserCreatedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public User $user
    ) {}

    public function getEventType(): string
    {
        return 'user.created';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->user->id,
                'email' => $this->user->email,
                'name' => $this->user->name,
                'organization_id' => $this->user->organization_id,
                'email_verified' => $this->user->email_verified_at !== null,
                'created_at' => $this->user->created_at?->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->user->organization_id,
        ];
    }
}
