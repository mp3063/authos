<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class WebhookDeliveryResource extends JsonResource
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
            'webhook_id' => $this->webhook_id,
            'event_type' => $this->event_type,
            'status' => $this->status?->value ?? $this->status,
            'http_status_code' => $this->http_status_code,
            'response_status' => $this->http_status_code, // Alias for backward compatibility
            'attempt_number' => $this->attempt_number,
            'attempt' => $this->attempt_number, // Alias for backward compatibility
            'max_attempts' => $this->max_attempts,
            'request_duration_ms' => $this->request_duration_ms,
            'response_time_ms' => $this->request_duration_ms, // Alias for backward compatibility
            'error_message' => $this->error_message,
            'next_retry_at' => $this->next_retry_at?->toISOString(),
            'sent_at' => $this->sent_at?->toISOString(),
            'completed_at' => $this->completed_at?->toISOString(),

            // Include payload for detailed view
            'payload' => $this->when(
                $request->route()->parameter('id') == $this->id ||
                $request->route()->parameter('deliveryId') == $this->id,
                $this->payload
            ),

            // Include response details for detailed view
            'response_body' => $this->when(
                $request->route()->parameter('id') == $this->id ||
                $request->route()->parameter('deliveryId') == $this->id,
                $this->response_body
            ),
            'response_headers' => $this->when(
                $request->route()->parameter('id') == $this->id ||
                $request->route()->parameter('deliveryId') == $this->id,
                $this->response_headers
            ),

            // Signature for verification
            'signature' => $this->when(
                $request->route()->parameter('id') == $this->id ||
                $request->route()->parameter('deliveryId') == $this->id,
                $this->signature
            ),

            // Webhook relationship
            'webhook' => new WebhookResource($this->whenLoaded('webhook')),

            // Timestamps
            'created_at' => $this->created_at?->toISOString(),
            'updated_at' => $this->updated_at?->toISOString(),
        ];
    }
}
