<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Laravel\Passport\Client;

class OAuthAuthorizationCode extends Model
{
    use HasFactory;

    protected $table = 'oauth_authorization_codes';

    protected $fillable = [
        'id',
        'user_id',
        'client_id',
        'scopes',
        'redirect_uri',
        'code_challenge',
        'code_challenge_method',
        'state',
        'expires_at',
        'revoked',
    ];

    protected $casts = [
        'scopes' => 'json',
        'expires_at' => 'datetime',
        'revoked' => 'boolean',
    ];

    protected $keyType = 'string';

    public $incrementing = false;

    /**
     * Get the user that owns the authorization code
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the client that the authorization code belongs to
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class);
    }

    /**
     * Check if the authorization code has expired
     */
    public function hasExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    /**
     * Check if the authorization code is valid
     */
    public function isValid(): bool
    {
        return ! $this->revoked && ! $this->hasExpired();
    }
}
