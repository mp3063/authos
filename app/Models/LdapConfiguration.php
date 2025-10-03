<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Crypt;

class LdapConfiguration extends Model
{
    use HasFactory;

    protected $fillable = [
        'organization_id',
        'name',
        'host',
        'port',
        'base_dn',
        'username',
        'password',
        'use_ssl',
        'use_tls',
        'user_filter',
        'user_attribute',
        'is_active',
        'last_sync_at',
        'sync_status',
        'last_sync_result',
        'last_sync_error',
        'sync_settings',
    ];

    protected $hidden = [
        'password',
    ];

    protected function casts(): array
    {
        return [
            'port' => 'integer',
            'use_ssl' => 'boolean',
            'use_tls' => 'boolean',
            'is_active' => 'boolean',
            'last_sync_at' => 'datetime',
            'last_sync_result' => 'array',
            'sync_settings' => 'array',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Get the encrypted password
     */
    public function getPasswordAttribute($value): ?string
    {
        return $value ? Crypt::decryptString($value) : null;
    }

    /**
     * Set the encrypted password
     */
    public function setPasswordAttribute($value): void
    {
        $this->attributes['password'] = $value ? Crypt::encryptString($value) : null;
    }

    /**
     * Get LDAP connection string
     */
    public function getConnectionString(): string
    {
        $protocol = $this->use_ssl ? 'ldaps' : 'ldap';

        return "{$protocol}://{$this->host}:{$this->port}";
    }

    /**
     * Check if configuration is testable
     */
    public function isTestable(): bool
    {
        return ! empty($this->host)
            && ! empty($this->base_dn)
            && ! empty($this->username)
            && ! empty($this->password);
    }

    /**
     * Scope: Active configurations
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }
}
