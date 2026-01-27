<?php

namespace App\Events;

use App\Models\CustomRole;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class RoleUpdatedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public CustomRole $role
    ) {}

    public function getEventType(): string
    {
        return 'role.updated';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->role->id,
                'name' => $this->role->name,
                'organization_id' => $this->role->organization_id,
                'updated_at' => $this->role->updated_at?->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->role->organization_id,
        ];
    }
}
