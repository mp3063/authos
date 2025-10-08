<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class IpBlocklist extends Model
{
    use HasFactory;

    protected $table = 'ip_blocklist';

    protected $fillable = [
        'ip_address',
        'block_type',
        'reason',
        'description',
        'blocked_at',
        'expires_at',
        'blocked_by',
        'incident_count',
        'metadata',
        'is_active',
    ];

    protected $casts = [
        'metadata' => 'array',
        'blocked_at' => 'datetime',
        'expires_at' => 'datetime',
        'is_active' => 'boolean',
        'incident_count' => 'integer',
    ];

    public function blockedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'blocked_by');
    }

    public function scopeActive($query)
    {
        return $query->where('is_active', true)
            ->where(function ($q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    public function isExpired(): bool
    {
        return ! is_null($this->expires_at) && $this->expires_at->isPast();
    }
}
