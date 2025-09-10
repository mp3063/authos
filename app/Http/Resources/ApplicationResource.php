<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ApplicationResource extends JsonResource
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
            'description' => $this->description,
            'client_id' => $this->client_id,
            'redirect_uris' => $this->redirect_uris,
            'allowed_scopes' => $this->allowed_scopes,
            'is_active' => $this->is_active,
            'logo_url' => $this->logo_url,
            'homepage_url' => $this->homepage_url,
            'privacy_policy_url' => $this->privacy_policy_url,
            'terms_of_service_url' => $this->terms_of_service_url,
            'organization_id' => $this->organization_id,
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),

            // Sensitive data only for authorized users
            'client_secret' => $this->when(
                $request->user()?->hasRole('super-admin') ||
                ($request->user()?->organization_id === $this->organization_id &&
                 $request->user()?->can('manage applications')),
                $this->client_secret
            ),

            // Relationships
            'organization' => new OrganizationResource($this->whenLoaded('organization')),
            'users' => UserResource::collection($this->whenLoaded('users')),
            'groups' => ApplicationGroupResource::collection($this->whenLoaded('groups')),

            // Computed attributes
            'users_count' => $this->when(
                isset($this->users_count),
                $this->users_count
            ),

            'active_sessions_count' => $this->when(
                isset($this->active_sessions_count),
                $this->active_sessions_count
            ),

            'last_used_at' => $this->when(
                isset($this->last_used_at),
                $this->last_used_at?->toISOString()
            ),
        ];
    }
}
