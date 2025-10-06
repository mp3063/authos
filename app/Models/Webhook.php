<?php

namespace App\Models;

use App\Traits\BelongsToOrganization;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

class Webhook extends Model
{
    use BelongsToOrganization;
    use HasFactory;
    use SoftDeletes;

    protected $fillable = [
        'organization_id',
        'name',
        'url',
        'secret',
        'events',
        'is_active',
        'description',
        'headers',
        'timeout_seconds',
        'ip_whitelist',
        'last_delivered_at',
        'last_failed_at',
        'failure_count',
        'consecutive_failures',
        'disabled_at',
        'delivery_stats',
        'metadata',
    ];

    protected $casts = [
        'events' => 'array',
        'is_active' => 'boolean',
        'headers' => 'array',
        'ip_whitelist' => 'array',
        'metadata' => 'array',
        'delivery_stats' => 'array',
        'secret' => 'encrypted',
        'last_delivered_at' => 'datetime',
        'last_failed_at' => 'datetime',
        'disabled_at' => 'datetime',
        'timeout_seconds' => 'integer',
        'failure_count' => 'integer',
        'consecutive_failures' => 'integer',
    ];

    protected $hidden = [
        'secret',
    ];

    /**
     * Relationships
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function deliveries(): HasMany
    {
        return $this->hasMany(WebhookDelivery::class);
    }

    /**
     * Scopes
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    public function scopeForEvent($query, string $eventType)
    {
        return $query->whereJsonContains('events', $eventType);
    }

    public function scopeSubscribedTo($query, string $eventType)
    {
        return $query->whereJsonContains('events', $eventType);
    }

    /**
     * Accessors & Mutators
     */
    public function getDecryptedSecretAttribute(): string
    {
        return $this->secret; // Already decrypted by encrypted cast
    }

    /**
     * Helper Methods
     */
    public function isSubscribedTo(string $eventType): bool
    {
        return in_array($eventType, $this->events ?? []);
    }

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
        $this->update(['last_failed_at' => now()]);
    }

    public function resetFailureCount(): void
    {
        $this->update([
            'failure_count' => 0,
            'last_delivered_at' => now(),
        ]);
    }

    public function shouldAutoDisable(): bool
    {
        return $this->failure_count >= 10;
    }

    public function enable(): void
    {
        $this->update([
            'is_active' => true,
            'disabled_at' => null,
            'consecutive_failures' => 0,
        ]);
    }

    public function averageResponseTime(): ?float
    {
        $stats = $this->delivery_stats;

        return $stats['average_response_time_ms'] ?? null;
    }

    public function updateDeliveryStats(bool $success, int $responseTimeMs): void
    {
        $stats = $this->delivery_stats ?? [
            'total_deliveries' => 0,
            'successful_deliveries' => 0,
            'failed_deliveries' => 0,
            'average_response_time_ms' => 0,
        ];

        $stats['total_deliveries']++;
        if ($success) {
            $stats['successful_deliveries']++;
        } else {
            $stats['failed_deliveries']++;
        }

        // Calculate new average response time
        $totalResponseTime = $stats['average_response_time_ms'] * ($stats['total_deliveries'] - 1);
        $stats['average_response_time_ms'] = ($totalResponseTime + $responseTimeMs) / $stats['total_deliveries'];

        $this->update(['delivery_stats' => $stats]);
    }

    public function getSuccessRate(int $days = 30): float
    {
        $total = $this->deliveries()
            ->where('created_at', '>=', now()->subDays($days))
            ->count();

        if ($total === 0) {
            return 0.0;
        }

        $successful = $this->deliveries()
            ->where('created_at', '>=', now()->subDays($days))
            ->where('status', 'success')
            ->count();

        return round(($successful / $total) * 100, 2);
    }

    public function getAverageDeliveryTime(int $days = 30): ?int
    {
        return $this->deliveries()
            ->where('created_at', '>=', now()->subDays($days))
            ->where('status', 'success')
            ->whereNotNull('request_duration_ms')
            ->avg('request_duration_ms');
    }
}
