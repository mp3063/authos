<?php

namespace App\Events;

use App\Models\User;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class MfaEnabledEvent implements ShouldDispatchAfterCommit
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public User $user
    ) {}

    public function getEventType(): string
    {
        return 'mfa.enabled';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'user_id' => $this->user->id,
                'email' => $this->user->email,
                'organization_id' => $this->user->organization_id,
                'enabled_at' => now()->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->user->organization_id,
        ];
    }
}
