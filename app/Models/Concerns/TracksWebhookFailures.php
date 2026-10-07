<?php

namespace App\Models\Concerns;

trait TracksWebhookFailures
{
    public function incrementFailures(): void
    {
        $this->increment('consecutive_failures');
        $this->increment('failure_count');
        $this->update(['last_failed_at' => now()]);
    }

    public function resetFailures(): void
    {
        $this->update([
            'consecutive_failures' => 0,
            'last_delivered_at' => now(),
        ]);
    }

    public function incrementFailureCount(): void
    {
        $this->increment('failure_count');
        $this->increment('consecutive_failures');
        $this->update(['last_failed_at' => now()]);
    }

    public function resetFailureCount(): void
    {
        $this->update([
            'failure_count' => 0,
            'consecutive_failures' => 0,
            'last_delivered_at' => now(),
        ]);
    }

    public function shouldAutoDisable(): bool
    {
        return $this->consecutive_failures >= 10;
    }

    public function enable(): void
    {
        $this->update([
            'is_active' => true,
            'disabled_at' => null,
            'consecutive_failures' => 0,
        ]);
    }
}
