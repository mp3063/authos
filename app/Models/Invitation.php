<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

/**
 * @method static \Illuminate\Database\Eloquent\Builder where($column, $operator = null, $value = null, $boolean = 'and')
 * @method static static create(array $attributes = [])
 * @method static static findOrFail($id, $columns = ['*'])
 * @method static \Illuminate\Database\Eloquent\Builder pending()
 * @method static \Illuminate\Database\Eloquent\Builder isExpired()
 * @method static \Illuminate\Database\Eloquent\Builder forOrganization($organizationId)
 *
 * @property-read Organization $organization
 * @property-read User|null $inviter
 */
class Invitation extends Model
{
    use HasFactory;

    protected $fillable = [
        'organization_id',
        'inviter_id',
        'email',
        'token',
        'role',
        'expires_at',
        'status',
        'metadata',
        'accepted_by',
        'accepted_at',
        'declined_at',
        'decline_reason',
        'cancelled_by',
        'cancelled_at',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'accepted_at' => 'datetime',
        'declined_at' => 'datetime',
        'cancelled_at' => 'datetime',
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
            if (empty($invitation->status)) {
                $invitation->status = 'pending';
            }
        });
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function inviter(): BelongsTo
    {
        return $this->belongsTo(User::class, 'inviter_id');
    }

    public function acceptor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'accepted_by');
    }

    public function acceptedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'accepted_by');
    }

    public function cancelledBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'cancelled_by');
    }

    /**
     * Scope: Pending invitations
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '>', now());
    }

    /**
     * Scope: Expired invitations
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '<=', now());
    }

    /**
     * Scope: Static method for expired invitations (alias for expired scope)
     */
    public function scopeIsExpired(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '<=', now());
    }

    /**
     * Scope: Accepted invitations
     */
    public function scopeAccepted(Builder $query): Builder
    {
        return $query->where('status', 'accepted');
    }

    /**
     * Scope: For specific organization
     */
    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }

    /**
     * Check if invitation is expired
     */
    public function hasExpired(): bool
    {
        return $this->expires_at < now();
    }

    /**
     * Check if invitation is pending
     */
    public function hasPending(): bool
    {
        return $this->status === 'pending' && ! $this->hasExpired();
    }

    /**
     * Instance method to check if invitation is expired
     */
    public function isExpired(): bool
    {
        return $this->hasExpired();
    }

    /**
     * Instance method to check if invitation is pending
     */
    public function isPending(): bool
    {
        return $this->hasPending();
    }

    /**
     * Check if invitation is accepted
     */
    public function isAccepted(): bool
    {
        return $this->status === 'accepted';
    }

    /**
     * Check if invitation can be accepted
     */
    public function canBeAccepted(): bool
    {
        return $this->status === 'pending' && ! $this->hasExpired();
    }

    /**
     * Accept the invitation
     */
    public function accept(User $user): bool
    {
        if (! $this->canBeAccepted()) {
            return false;
        }

        $this->update([
            'status' => 'accepted',
            'accepted_at' => now(),
            'accepted_by' => $user->id,
        ]);

        return true;
    }

    /**
     * Mark invitation as accepted
     */
    public function markAsAccepted(User|int $user): bool
    {
        if ($user instanceof User) {
            return $this->accept($user);
        }

        $userModel = User::find($user);

        return $userModel ? $this->accept($userModel) : false;
    }

    /**
     * Mark invitation as declined
     */
    public function markAsDeclined(?string $reason = null): bool
    {
        if ($this->status !== 'pending') {
            return false;
        }

        $this->update([
            'status' => 'declined',
            'declined_at' => now(),
            'decline_reason' => $reason,
        ]);

        return true;
    }

    /**
     * Mark invitation as cancelled
     */
    public function markAsCancelled(User|int $user): bool
    {
        if ($this->status !== 'pending') {
            return false;
        }

        $userId = $user instanceof User ? $user->id : $user;

        $this->update([
            'status' => 'cancelled',
            'cancelled_at' => now(),
            'cancelled_by' => $userId,
        ]);

        return true;
    }

    /**
     * Generate a new token
     */
    public function generateNewToken(): string
    {
        $token = Str::random(64);
        $this->update(['token' => $token]);

        return $token;
    }

    /**
     * Regenerate token and extend expiry
     */
    public function regenerateToken(int $days = 7): string
    {
        $token = Str::random(32); // Use 32 chars as expected by tests
        $this->update([
            'token' => $token,
            'expires_at' => now()->addDays($days),
        ]);

        return $token;
    }

    /**
     * Extend invitation expiry
     */
    public function extend(int $days = 7): void
    {
        $this->update([
            'expires_at' => now()->addDays($days),
        ]);
    }

    /**
     * Get invitation URL
     */
    public function getInvitationUrl(): string
    {
        return url("/invitations/accept/{$this->token}");
    }

    /**
     * Get days until expiry
     */
    public function daysUntilExpiry(): int
    {
        return (int) ceil(now()->diffInDays($this->expires_at, false));
    }

    /**
     * Find invitation by token
     */
    public static function findByToken(string $token): ?self
    {
        return static::where('token', $token)->first();
    }

    /**
     * Scope: isPending (static callable)
     */
    public function scopeIsPending(Builder $query): Builder
    {
        return $query->where('status', 'pending')
            ->where('expires_at', '>', now());
    }
}
