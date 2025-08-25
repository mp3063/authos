<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class AuthenticationLog extends Model
{
    use HasFactory;

    public $timestamps = false;
    
    protected $fillable = [
        'user_id',
        'application_id',
        'event',
        'ip_address',
        'user_agent',
        'metadata',
        'created_at',
    ];

    protected $casts = [
        'metadata' => 'array',
        'created_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function application(): BelongsTo
    {
        return $this->belongsTo(Application::class);
    }

    public function getEventBadgeColor(): string
    {
        return match ($this->event) {
            'login', 'token_refresh', 'mfa_success' => 'success',
            'logout' => 'info',
            'failed_login', 'failed_mfa', 'suspicious_activity' => 'danger',
            'mfa_challenge', 'password_reset' => 'warning',
            default => 'gray',
        };
    }

    public function getEventIcon(): string
    {
        return match ($this->event) {
            'login' => 'heroicon-o-arrow-right-on-rectangle',
            'logout' => 'heroicon-o-arrow-left-on-rectangle',
            'failed_login' => 'heroicon-o-x-circle',
            'token_refresh' => 'heroicon-o-arrow-path',
            'mfa_challenge', 'mfa_success', 'failed_mfa' => 'heroicon-o-shield-check',
            'password_reset' => 'heroicon-o-key',
            'suspicious_activity' => 'heroicon-o-exclamation-triangle',
            default => 'heroicon-o-information-circle',
        };
    }
}