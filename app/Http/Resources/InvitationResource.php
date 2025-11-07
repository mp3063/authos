<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class InvitationResource extends JsonResource
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
            'organization_id' => $this->organization_id,
            'invited_by' => $this->invited_by,
            'accepted_by' => $this->accepted_by,
            'role' => $this->role,
            'status' => $this->status,
            'expires_at' => $this->expires_at?->toISOString(),
            'accepted_at' => $this->accepted_at?->toISOString(),
            'metadata' => $this->metadata,
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),

            // Include token for pending invitations
            'token' => $this->when(
                $this->status === 'pending',
                $this->token
            ),

            // Include invitation URL for pending invitations
            'invitation_url' => $this->when(
                $this->status === 'pending',
                url("/api/v1/invitations/{$this->token}")
            ),

            // Relationships
            'organization' => new OrganizationResource($this->whenLoaded('organization')),
            'inviter' => new UserResource($this->whenLoaded('inviter')),
            'acceptedBy' => new UserResource($this->whenLoaded('acceptedBy')),

            // Computed attributes
            'is_expired' => $this->when(
                method_exists($this->resource, 'isExpired'),
                $this->isExpired()
            ),

            'is_pending' => $this->when(
                method_exists($this->resource, 'isPending'),
                $this->isPending()
            ),

            'can_be_accepted' => $this->when(
                method_exists($this->resource, 'canBeAccepted'),
                $this->canBeAccepted()
            ),

            'days_until_expiry' => $this->when(
                method_exists($this->resource, 'daysUntilExpiry'),
                $this->daysUntilExpiry()
            ),
        ];
    }
}
