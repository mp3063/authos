<?php

namespace App\Events;

use App\Models\Application;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ApplicationUpdatedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public Application $application
    ) {}

    public function getEventType(): string
    {
        return 'application.updated';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->application->id,
                'name' => $this->application->name,
                'organization_id' => $this->application->organization_id,
                'type' => $this->application->type,
                'updated_at' => $this->application->updated_at?->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->application->organization_id,
        ];
    }
}
