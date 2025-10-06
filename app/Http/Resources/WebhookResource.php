<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class WebhookResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'url' => $this->url,
            'events' => $this->events,
            'is_active' => $this->is_active,
            'description' => $this->description,
            'custom_headers' => $this->headers,
            'timeout_seconds' => $this->timeout_seconds,
            'ip_whitelist' => $this->ip_whitelist,
            'last_delivered_at' => $this->last_delivered_at?->toISOString(),
            'last_failed_at' => $this->last_failed_at?->toISOString(),
            'failure_count' => $this->failure_count,
            'metadata' => $this->metadata,
            'organization_id' => $this->organization_id,

            // Include secret only on creation or for authorized users
            'secret' => $this->when(
                $request->route()->getActionMethod() === 'store' ||
                $request->route()->getActionMethod() === 'rotateSecret',
                $this->decrypted_secret
            ),

            // Relationships
            'organization' => new OrganizationResource($this->whenLoaded('organization')),

            // Statistics (when loaded)
            'total_deliveries' => $this->when(
                isset($this->total_deliveries),
                $this->total_deliveries
            ),
            'success_rate' => $this->when(
                isset($this->success_rate),
                $this->success_rate
            ),
            'average_delivery_time_ms' => $this->when(
                isset($this->average_delivery_time_ms),
                $this->average_delivery_time_ms
            ),

            // Timestamps
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),
            'deleted_at' => $this->when($this->deleted_at, $this->deleted_at?->toISOString()),
        ];
    }
}
