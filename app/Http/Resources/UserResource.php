<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
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
            'email' => $this->email,
            'name' => $this->name,
            'is_active' => $this->is_active,
            'avatar_url' => $this->avatar_url,
            'timezone' => $this->timezone,
            'locale' => $this->locale,
            'email_verified_at' => $this->email_verified_at?->toISOString(),
            'last_login_at' => $this->last_login_at?->toISOString(),
            'mfa_enabled' => $this->mfa_enabled,
            'social_providers' => $this->social_providers,
            'organization_id' => $this->organization_id,
            'organization' => new OrganizationResource($this->whenLoaded('organization')),
            'roles' => RoleResource::collection($this->whenLoaded('roles')),
            'applications' => ApplicationResource::collection($this->whenLoaded('applications')),
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),

            // Computed attributes
            'permissions' => $this->when($this->relationLoaded('roles'), function () {
                return $this->roles->flatMap->permissions->pluck('name')->unique()->values();
            }),

            'applications_count' => $this->when(
                isset($this->applications_count),
                $this->applications_count
            ),

            'last_activity' => $this->when(
                isset($this->last_activity),
                $this->last_activity?->toISOString()
            ),
        ];
    }
}
