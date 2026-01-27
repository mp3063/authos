<?php

namespace App\Events;

use App\Models\Webhook;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class WebhookUpdatedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public Webhook $webhook
    ) {}

    public function getEventType(): string
    {
        return 'webhook.updated';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->webhook->id,
                'name' => $this->webhook->name,
                'url' => $this->webhook->url,
                'organization_id' => $this->webhook->organization_id,
                'events' => $this->webhook->events,
                'updated_at' => $this->webhook->updated_at?->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->webhook->organization_id,
        ];
    }
}
