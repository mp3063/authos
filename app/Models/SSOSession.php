<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Support\Str;
use Carbon\Carbon;

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
        'metadata',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'last_activity_at' => 'datetime',
        'metadata' => 'array',
    ];

    protected static function boot()
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

    public function scopeActive($query)
    {
        return $query->where('expires_at', '>', now());
    }

    public function scopeExpired($query)
    {
        return $query->where('expires_at', '<=', now());
    }

    public function isExpired(): bool
    {
        return $this->expires_at < now();
    }

    public function isActive(): bool
    {
        return !$this->isExpired();
    }

    public function updateActivity(): void
    {
        $this->update(['last_activity_at' => now()]);
    }

    public function extend(int $seconds = null): void
    {
        $config = $this->application->ssoConfiguration;
        $lifetime = $seconds ?? $config->session_lifetime ?? 3600;

        $this->update([
            'expires_at' => now()->addSeconds($lifetime),
            'last_activity_at' => now(),
        ]);
    }

    public function revoke(): bool
    {
        return $this->update(['expires_at' => now()->subSecond()]);
    }

    public function refresh(): string
    {
        $newRefreshToken = Str::random(64);
        $this->update([
            'refresh_token' => $newRefreshToken,
            'last_activity_at' => now(),
        ]);
        
        return $newRefreshToken;
    }
}
