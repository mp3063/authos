<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityIncident extends Model
{
    use HasFactory;

    protected $fillable = [
        'type',
        'severity',
        'ip_address',
        'user_agent',
        'user_id',
        'endpoint',
        'description',
        'metadata',
        'status',
        'detected_at',
        'resolved_at',
        'resolution_notes',
        'action_taken',
    ];

    protected $casts = [
        'metadata' => 'array',
        'detected_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function scopeOpen($query)
    {
        return $query->where('status', 'open');
    }

    public function scopeCritical($query)
    {
        return $query->where('severity', 'critical');
    }

    public function scopeByType($query, string $type)
    {
        return $query->where('type', $type);
    }
}
