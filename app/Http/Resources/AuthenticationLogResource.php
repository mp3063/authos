<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class AuthenticationLogResource extends JsonResource
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
            'event' => $this->event,
            'user_id' => $this->user_id,
            'organization_id' => $this->organization_id,
            'application_id' => $this->application_id,
            'ip_address' => $this->ip_address,
            'user_agent' => $this->user_agent,
            'location' => $this->location,
            'risk_level' => $this->risk_level,
            'status' => $this->status,
            'details' => $this->details,
            'created_at' => $this->created_at?->toISOString(),

            // Relationships
            'user' => new UserResource($this->whenLoaded('user')),
            'organization' => new OrganizationResource($this->whenLoaded('organization')),
            'application' => new ApplicationResource($this->whenLoaded('application')),

            // Computed attributes
            'is_suspicious' => $this->when(
                $this->risk_level === 'high' ||
                in_array($this->event, ['login_failed', 'brute_force_detected', 'suspicious_activity']),
                true
            ),

            'event_category' => $this->when(
                in_array($this->event, ['login', 'logout', 'login_failed']),
                'authentication'
            ) ?: 'system',

            'device_info' => $this->when(
                ! empty($this->details['device']),
                $this->details['device'] ?? null
            ),
        ];
    }
}
