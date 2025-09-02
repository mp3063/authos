<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Support\Str;
use Carbon\Carbon;

/**
 * @method static \Illuminate\Database\Eloquent\Builder where($column, $operator = null, $value = null, $boolean = 'and')
 * @method static static create(array $attributes = [])
 * @method static static findOrFail($id, $columns = ['*'])
 * @method static \Illuminate\Database\Eloquent\Builder pending()
 * @property-read Organization $organization
 * @property-read User|null $invitedBy
 */
class Invitation extends Model
{
    use HasFactory;

    protected $fillable = [
        'organization_id',
        'email',
        'role',
        'token',
        'invited_by',
        'expires_at',
        'accepted_at',
        'accepted_by',
        'metadata',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'accepted_at' => 'datetime',
        'metadata' => 'array',
    ];

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($invitation) {
            if (empty($invitation->token)) {
                $invitation->token = Str::random(64);
            }
            if (empty($invitation->expires_at)) {
                $invitation->expires_at = Carbon::now()->addDays(7);
            }
        });
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function inviter(): BelongsTo
    {
        return $this->belongsTo(User::class, 'invited_by');
    }

    public function acceptor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'accepted_by');
    }

    public function scopePending($query)
    {
        return $query->whereNull('accepted_at')->where('expires_at', '>', now());
    }

    public function scopeExpired($query)
    {
        return $query->whereNull('accepted_at')->where('expires_at', '<=', now());
    }

    public function scopeAccepted($query)
    {
        return $query->whereNotNull('accepted_at');
    }

    public function isExpired(): bool
    {
        return $this->expires_at < now();
    }

    public function isPending(): bool
    {
        return is_null($this->accepted_at) && !$this->isExpired();
    }

    public function isAccepted(): bool
    {
        return !is_null($this->accepted_at);
    }

    public function accept(User $user): bool
    {
        if (!$this->isPending()) {
            return false;
        }

        $this->update([
            'accepted_at' => now(),
            'accepted_by' => $user->id,
        ]);

        return true;
    }

    public function generateNewToken(): string
    {
        $token = Str::random(64);
        $this->update(['token' => $token]);
        return $token;
    }

    public function extend(int $days = 7): void
    {
        $this->update([
            'expires_at' => now()->addDays($days)
        ]);
    }
}
