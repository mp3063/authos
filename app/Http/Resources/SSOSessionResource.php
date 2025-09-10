<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class SSOSessionResource extends JsonResource
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
            'user_id' => $this->user_id,
            'application_id' => $this->application_id,
            'session_id' => $this->session_id,
            'provider' => $this->provider,
            'provider_session_id' => $this->provider_session_id,
            'ip_address' => $this->ip_address,
            'user_agent' => $this->user_agent,
            'last_activity_at' => $this->last_activity_at?->toISOString(),
            'expires_at' => $this->expires_at?->toISOString(),
            'logged_out_at' => $this->logged_out_at?->toISOString(),
            'metadata' => $this->metadata,
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),

            // Hide sensitive tokens
            'access_token' => $this->when(false, null),
            'refresh_token' => $this->when(false, null),

            // Relationships
            'user' => new UserResource($this->whenLoaded('user')),
            'application' => new ApplicationResource($this->whenLoaded('application')),

            // Computed attributes
            'is_active' => $this->when(
                method_exists($this->resource, 'isActive'),
                $this->isActive()
            ),

            'is_expired' => $this->when(
                method_exists($this->resource, 'isExpired'),
                $this->isExpired()
            ),

            'minutes_since_activity' => $this->when(
                method_exists($this->resource, 'minutesSinceLastActivity'),
                $this->minutesSinceLastActivity()
            ),

            'device_info' => $this->when(
                method_exists($this->resource, 'getDeviceInfo'),
                $this->getDeviceInfo()
            ),

            'location_info' => $this->when(
                method_exists($this->resource, 'getLocationInfo'),
                $this->getLocationInfo()
            ),

            'is_suspicious' => $this->when(
                method_exists($this->resource, 'isSuspicious'),
                $this->isSuspicious()
            ),
        ];
    }
}
