<?php

namespace App\Models;

use App\Traits\BelongsToOrganization;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\Crypt;

class Webhook extends Model
{
    use BelongsToOrganization, HasFactory, SoftDeletes;

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
        'metadata',
    ];

    protected $casts = [
        'events' => 'array',
        'is_active' => 'boolean',
        'headers' => 'array',
        'ip_whitelist' => 'array',
        'metadata' => 'array',
        'last_delivered_at' => 'datetime',
        'last_failed_at' => 'datetime',
        'timeout_seconds' => 'integer',
        'failure_count' => 'integer',
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

    public function scopeSubscribedTo($query, string $eventType)
    {
        return $query->whereJsonContains('events', $eventType);
    }

    /**
     * Accessors & Mutators
     */
    public function getDecryptedSecretAttribute(): string
    {
        return Crypt::decryptString($this->secret);
    }

    public function setSecretAttribute($value): void
    {
        $this->attributes['secret'] = Crypt::encryptString($value);
    }

    /**
     * Helper Methods
     */
    public function isSubscribedTo(string $eventType): bool
    {
        return in_array($eventType, $this->events ?? []);
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
