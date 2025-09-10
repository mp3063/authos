<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class RoleResource extends JsonResource
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
            'display_name' => $this->display_name ?? $this->name,
            'description' => $this->description,
            'guard_name' => $this->guard_name,
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),

            // Relationships
            'permissions' => PermissionResource::collection($this->whenLoaded('permissions')),

            // Computed attributes
            'users_count' => $this->when(
                isset($this->users_count),
                $this->users_count
            ),

            'permissions_count' => $this->when(
                isset($this->permissions_count),
                $this->permissions_count
            ),

            'is_system_role' => $this->when(
                method_exists($this, 'isSystemRole'),
                function () {
                    return method_exists($this, 'isSystemRole') ? $this->isSystemRole() : false;
                }
            ),
        ];
    }
}
