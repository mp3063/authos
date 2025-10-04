<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class CustomDomain extends Model
{
    use HasFactory;

    protected $fillable = [
        'organization_id',
        'domain',
        'status',
        'verification_code',
        'verification_method',
        'verified_at',
        'ssl_certificate',
        'dns_records',
        'is_active',
        'settings',
    ];

    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime',
            'ssl_certificate' => 'array',
            'dns_records' => 'array',
            'is_active' => 'boolean',
            'settings' => 'array',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Check if domain is verified
     */
    public function isVerified(): bool
    {
        return $this->verified_at !== null;
    }

    /**
     * Generate verification code (32-char hex)
     */
    public static function generateVerificationCode(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Get DNS records for verification
     */
    public function getVerificationDnsRecords(): array
    {
        return [
            [
                'type' => 'TXT',
                'name' => '_authos-verify',
                'value' => $this->verification_code,
                'ttl' => 3600,
            ],
            [
                'type' => 'CNAME',
                'name' => '@',
                'value' => config('app.domain', 'authos.app'),
                'ttl' => 3600,
            ],
        ];
    }

    /**
     * Scope: Active domains
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true)->whereNotNull('verified_at');
    }

    /**
     * Scope: Verified domains
     */
    public function scopeVerified($query)
    {
        return $query->whereNotNull('verified_at');
    }
}
