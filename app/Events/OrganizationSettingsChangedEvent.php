<?php

namespace App\Events;

use App\Models\Organization;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class OrganizationSettingsChangedEvent implements ShouldDispatchAfterCommit
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public Organization $organization,
        public array $changedSettings = []
    ) {}

    public function getEventType(): string
    {
        return 'organization.settings_changed';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->organization->id,
                'name' => $this->organization->name,
                'changed_settings' => $this->changedSettings,
                'updated_at' => $this->organization->updated_at instanceof \DateTimeInterface
                    ? $this->organization->updated_at->toIso8601String()
                    : $this->organization->updated_at,
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->organization->id,
        ];
    }
}
