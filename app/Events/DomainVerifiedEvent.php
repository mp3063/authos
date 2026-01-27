<?php

namespace App\Events;

use App\Models\CustomDomain;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class DomainVerifiedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public CustomDomain $domain
    ) {}

    public function getEventType(): string
    {
        return 'domain.verified';
    }

    public function getPayload(): array
    {
        return [
            'event' => $this->getEventType(),
            'data' => [
                'id' => $this->domain->id,
                'domain' => $this->domain->domain,
                'organization_id' => $this->domain->organization_id,
                'verified_at' => $this->domain->verified_at?->toIso8601String(),
            ],
            'timestamp' => now()->toIso8601String(),
            'organization_id' => $this->domain->organization_id,
        ];
    }
}
