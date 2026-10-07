<?php

namespace App\Models;

use App\Enums\WebhookDeliveryStatus;
use App\Models\Concerns\HasDeliveryRetries;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class WebhookDelivery extends Model
{
    use HasDeliveryRetries;
    use HasFactory;

    protected $fillable = [
        'webhook_id',
        'event_type',
        'payload',
        'status',
        'http_status_code',
        'response_body',
        'response_headers',
        'error_message',
        'attempt_number',
        'max_attempts',
        'next_retry_at',
        'signature',
        'request_duration_ms',
        'sent_at',
        'completed_at',
    ];

    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'response_headers' => 'array',
            'http_status_code' => 'integer',
            'attempt_number' => 'integer',
            'max_attempts' => 'integer',
            'request_duration_ms' => 'integer',
            'next_retry_at' => 'datetime',
            'sent_at' => 'datetime',
            'completed_at' => 'datetime',
            'status' => WebhookDeliveryStatus::class,
        ];
    }

    /**
     * Relationships
     */
    public function webhook(): BelongsTo
    {
        return $this->belongsTo(Webhook::class);
    }

    /**
     * Scopes
     */
    public function scopePending($query)
    {
        return $query->where('status', WebhookDeliveryStatus::PENDING);
    }

    public function scopeSuccessful($query)
    {
        return $query->where('status', WebhookDeliveryStatus::SUCCESS);
    }

    public function scopeFailed($query)
    {
        return $query->where('status', WebhookDeliveryStatus::FAILED);
    }

    public function scopeEventType($query, string $eventType)
    {
        return $query->where('event_type', $eventType);
    }

    /**
     * Helper Methods
     */
    public function isSuccessful(): bool
    {
        return $this->status === WebhookDeliveryStatus::SUCCESS;
    }

    public function isFailed(): bool
    {
        return $this->status === WebhookDeliveryStatus::FAILED;
    }

    public function markAsSending(): void
    {
        $this->update([
            'status' => WebhookDeliveryStatus::SENDING,
            'sent_at' => now(),
        ]);
    }

    public function markAsSuccess(int $httpStatus, string $responseBody, array $headers, int $durationMs): void
    {
        $this->update([
            'status' => WebhookDeliveryStatus::SUCCESS,
            'http_status_code' => $httpStatus,
            'response_body' => substr($responseBody, 0, 10000), // Limit to 10KB
            'response_headers' => $headers,
            'request_duration_ms' => $durationMs,
            'completed_at' => now(),
            'error_message' => null,
        ]);
    }

    public function markAsFailed(int $httpStatus, string $error, ?string $responseBody = null): void
    {
        $this->update([
            'status' => WebhookDeliveryStatus::FAILED,
            'http_status_code' => $httpStatus,
            'error_message' => $error,
            'response_body' => $responseBody ? substr($responseBody, 0, 10000) : null,
            'completed_at' => now(),
        ]);
    }

    /**
     * Truncate response body for storage
     */
    public function setResponseBodyAttribute($value): void
    {
        $this->attributes['response_body'] = $value ? substr($value, 0, 10000) : null;
    }
}
