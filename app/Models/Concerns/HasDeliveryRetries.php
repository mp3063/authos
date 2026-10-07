<?php

namespace App\Models\Concerns;

use App\Enums\WebhookDeliveryStatus;
use Illuminate\Database\Eloquent\Casts\Attribute;

trait HasDeliveryRetries
{
    public function scopeRetryable($query)
    {
        return $query->where('status', WebhookDeliveryStatus::RETRYING)
            ->whereNotNull('next_retry_at')
            ->where('next_retry_at', '<=', now());
    }

    protected function willRetry(): Attribute
    {
        return Attribute::get(fn (): bool => $this->canRetry());
    }

    public function canRetry(): bool
    {
        return $this->attempt_number < $this->max_attempts &&
               in_array($this->status, [WebhookDeliveryStatus::FAILED, WebhookDeliveryStatus::RETRYING]);
    }

    public function hasReachedMaxAttempts(): bool
    {
        return $this->attempt_number >= $this->max_attempts;
    }

    public function scheduleRetry(int $delayMinutes): void
    {
        $this->increment('attempt_number');

        $this->update([
            'status' => WebhookDeliveryStatus::RETRYING,
            'next_retry_at' => now()->addMinutes($delayMinutes),
        ]);
    }

    public function getRetryDelay(): int
    {
        // Exponential backoff: 1min, 5min, 15min, 1hr, 6hr, 24hr
        return match ($this->attempt_number) {
            1 => 1,
            2 => 5,
            3 => 15,
            4 => 60,
            5 => 360,
            default => 1440,
        };
    }
}
