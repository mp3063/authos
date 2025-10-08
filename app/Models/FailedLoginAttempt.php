<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class FailedLoginAttempt extends Model
{
    use HasFactory;

    protected $fillable = [
        'email',
        'ip_address',
        'user_agent',
        'attempt_type',
        'failure_reason',
        'metadata',
        'attempted_at',
    ];

    protected $casts = [
        'metadata' => 'array',
        'attempted_at' => 'datetime',
    ];

    public function scopeRecentAttempts($query, string $identifier, int $minutes = 15)
    {
        return $query->where(function ($q) use ($identifier) {
            $q->where('email', $identifier)
                ->orWhere('ip_address', $identifier);
        })->where('attempted_at', '>=', now()->subMinutes($minutes));
    }
}
