<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ApplicationGroupResource extends JsonResource
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
            'organization_id' => $this->organization_id,
            'parent_id' => $this->parent_id,
            'is_active' => $this->is_active,
            'settings' => $this->settings,
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),

            // Relationships
            'parent' => new ApplicationGroupResource($this->whenLoaded('parent')),
            'children' => ApplicationGroupResource::collection($this->whenLoaded('children')),
            'applications' => ApplicationResource::collection($this->whenLoaded('applications')),
            'organization' => new OrganizationResource($this->whenLoaded('organization')),

            // Computed attributes
            'applications_count' => $this->when(
                isset($this->applications_count),
                $this->applications_count
            ),

            'depth' => $this->when(
                method_exists($this->resource, 'getDepth'),
                $this->getDepth()
            ),

            'full_path' => $this->when(
                method_exists($this->resource, 'getFullPath'),
                $this->getFullPath()
            ),

            'has_children' => $this->when(
                method_exists($this->resource, 'hasChildren'),
                $this->hasChildren()
            ),
        ];
    }
}
