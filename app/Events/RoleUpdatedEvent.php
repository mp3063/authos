<?php

namespace App\Events;

use App\Models\CustomRole;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class RoleUpdatedEvent implements ShouldDispatchAfterCommit
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
                'updated_at' => $this->role->updated_at instanceof \DateTimeInterface
                    ? $this->role->updated_at->toIso8601String()
                    : $this->role->updated_at,
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->role->organization_id,
        ];
    }
}
