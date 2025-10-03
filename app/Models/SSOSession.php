<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class SSOSession extends Model
{
    use HasFactory;

    protected $table = 'sso_sessions';

    protected $fillable = [
        'user_id',
        'application_id',
        'session_token',
        'refresh_token',
        'external_session_id',
        'ip_address',
        'user_agent',
        'expires_at',
        'last_activity_at',
        'logged_out_at',
        'logged_out_by',
        'metadata',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'last_activity_at' => 'datetime',
        'logged_out_at' => 'datetime',
        'metadata' => 'array',
    ];

    protected static function boot(): void
    {
        parent::boot();

        static::creating(function ($session) {
            if (empty($session->session_token)) {
                $session->session_token = Str::random(64);
            }
            if (empty($session->refresh_token)) {
                $session->refresh_token = Str::random(64);
            }
            if (empty($session->last_activity_at)) {
                $session->last_activity_at = now();
            }
        });
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function application(): BelongsTo
    {
        return $this->belongsTo(Application::class);
    }

    public function loggedOutBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'logged_out_by');
    }

    /**
     * Scope: Active sessions
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('expires_at', '>', now())
            ->whereNull('logged_out_at');
    }

    /**
     * Scope: Expired sessions
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query->where('expires_at', '<=', now());
    }

    /**
     * Scope: Sessions for specific user
     */
    public function scopeForUser(Builder $query, int $userId): Builder
    {
        return $query->where('user_id', $userId);
    }

    /**
     * Scope: Sessions for specific application
     */
    public function scopeForApplication(Builder $query, int $applicationId): Builder
    {
        return $query->where('application_id', $applicationId);
    }

    /**
     * Check if session is expired
     */
    public function isExpired(): bool
    {
        return $this->expires_at < now();
    }

    /**
     * Check if session is active
     */
    public function isActive(): bool
    {
        return ! $this->isExpired() && is_null($this->logged_out_at);
    }

    /**
     * Extend session expiry
     */
    public function extendSession(int $seconds = 3600): void
    {
        $newExpiry = $this->expires_at->copy()->addSeconds($seconds);

        $this->update([
            'expires_at' => $newExpiry,
            'last_activity_at' => now(),
        ]);

        $this->refresh();
    }

    /**
     * Update last activity timestamp
     */
    public function updateLastActivity(): void
    {
        $this->update(['last_activity_at' => now()]);
    }

    /**
     * Logout the session
     */
    public function logout(User|int|null $user = null): bool
    {
        $userId = $user instanceof User ? $user->id : $user;

        return $this->update([
            'logged_out_at' => now(),
            'logged_out_by' => $userId,
        ]);
    }

    /**
     * Generate new session token
     */
    public function generateNewSessionToken(): string
    {
        $token = Str::random(64);
        $this->update(['session_token' => $token]);

        return $token;
    }

    /**
     * Generate new refresh token
     */
    public function generateNewRefreshToken(): string
    {
        $token = Str::random(64);
        $this->update(['refresh_token' => $token]);

        return $token;
    }

    /**
     * Get device information from metadata
     */
    public function getDeviceInfo(): array
    {
        $metadata = $this->metadata ?? [];

        return [
            'device' => $metadata['device'] ?? $metadata['device_type'] ?? 'unknown',
            'browser' => $metadata['browser'] ?? 'unknown',
            'platform' => $metadata['platform'] ?? $metadata['os'] ?? 'unknown',
        ];
    }

    /**
     * Get location information from metadata
     */
    public function getLocationInfo(): array
    {
        $metadata = $this->metadata ?? [];
        $location = $metadata['location'] ?? [];

        return [
            'country' => $location['country'] ?? $metadata['country'] ?? null,
            'city' => $location['city'] ?? $metadata['city'] ?? null,
            'region' => $location['region'] ?? $metadata['region'] ?? null,
            'timezone' => $location['timezone'] ?? $metadata['timezone'] ?? null,
        ];
    }

    /**
     * Check if session is suspicious
     */
    public function isSuspicious(): bool
    {
        $metadata = $this->metadata ?? [];

        // Check for explicit suspicious flags or risk factors
        if (isset($metadata['suspicious_flags']) && count($metadata['suspicious_flags']) > 0) {
            return true;
        }

        if (isset($metadata['risk_factors']) && count($metadata['risk_factors']) > 0) {
            return true;
        }

        // Check risk score
        if (isset($metadata['risk_score']) && $metadata['risk_score'] > 70) {
            return true;
        }

        // Check for rapid IP changes (basic check)
        if (isset($metadata['ip_history']) && count($metadata['ip_history']) > 5) {
            return true;
        }

        return false;
    }

    /**
     * Get minutes since last activity
     */
    public function minutesSinceLastActivity(): int
    {
        return (int) abs(now()->diffInMinutes($this->last_activity_at));
    }

    /**
     * Get hours until expiry
     */
    public function hoursUntilExpiry(): int
    {
        if ($this->isExpired()) {
            return 0;
        }

        return (int) round(now()->diffInHours($this->expires_at));
    }

    /**
     * Legacy method aliases for backward compatibility
     */
    public function updateActivity(): void
    {
        $this->updateLastActivity();
    }

    public function extend(?int $seconds = null): void
    {
        $this->extendSession($seconds ?? 3600);
    }

    public function revoke(): bool
    {
        return $this->logout();
    }

    public function refresh(): string
    {
        $this->updateLastActivity();

        return $this->generateNewRefreshToken();
    }

    /**
     * Find session by session token
     */
    public static function findBySessionToken(string $token): ?self
    {
        return static::where('session_token', $token)->first();
    }

    /**
     * Cleanup expired sessions
     */
    public static function cleanupExpired(): int
    {
        /** @var int $deleted */
        $deleted = static::expired()->delete();

        return $deleted;
    }
}
