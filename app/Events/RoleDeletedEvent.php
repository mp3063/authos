<?php

namespace App\Events;

use App\Models\CustomRole;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class RoleDeletedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public CustomRole $role
    ) {}

    public function getEventType(): string
    {
        return 'role.deleted';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->role->id,
                'name' => $this->role->name,
                'organization_id' => $this->role->organization_id,
                'deleted_at' => now()->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->role->organization_id,
        ];
    }
}
