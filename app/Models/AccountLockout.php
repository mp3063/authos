<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AccountLockout extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'email',
        'ip_address',
        'lockout_type',
        'attempt_count',
        'locked_at',
        'unlock_at',
        'unlocked_at',
        'unlock_method',
        'reason',
        'metadata',
    ];

    protected $casts = [
        'metadata' => 'array',
        'locked_at' => 'datetime',
        'unlock_at' => 'datetime',
        'unlocked_at' => 'datetime',
        'attempt_count' => 'integer',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function isActive(): bool
    {
        return is_null($this->unlocked_at) &&
               (is_null($this->unlock_at) || $this->unlock_at->isFuture());
    }

    public function isExpired(): bool
    {
        return ! is_null($this->unlock_at) && $this->unlock_at->isPast();
    }
}
