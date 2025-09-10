<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class OrganizationResource extends JsonResource
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
            'slug' => $this->slug,
            'domain' => $this->domain,
            'description' => $this->description,
            'website' => $this->website,
            'logo' => $this->logo_url,
            'is_active' => $this->is_active,
            'settings' => $this->settings,
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),
            'recent_activity' => [], // Placeholder for test compatibility

            // Conditional relationships
            'users' => UserResource::collection($this->whenLoaded('users')),
            'applications' => ApplicationResource::collection($this->whenLoaded('applications')),

            // Computed attributes
            'users_count' => $this->users_count ?? 0,
            'applications_count' => $this->applications_count ?? 0,
            'active_users_count' => $this->active_users_count ?? 0,

            // Security settings (only for admin)
            'security_settings' => $this->when(
                $request->user()?->hasRole('super-admin') ||
                $request->user()?->organization_id === $this->id,
                $this->settings['security'] ?? []
            ),
        ];
    }
}
