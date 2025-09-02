<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class SSOConfiguration extends Model
{
    use HasFactory;

    protected $table = 'sso_configurations';

    protected $fillable = [
        'application_id',
        'logout_url',
        'callback_url',
        'allowed_domains',
        'session_lifetime',
        'settings',
        'is_active',
    ];

    protected $casts = [
        'allowed_domains' => 'array',
        'settings' => 'array',
        'is_active' => 'boolean',
    ];

    public function application(): BelongsTo
    {
        return $this->belongsTo(Application::class);
    }

    public function isAllowedDomain(string $domain): bool
    {
        if (empty($this->allowed_domains)) {
            return false;
        }

        $allowedDomains = $this->allowed_domains;
        
        // Check for exact match
        if (in_array($domain, $allowedDomains)) {
            return true;
        }

        // Check for wildcard matches
        foreach ($allowedDomains as $allowedDomain) {
            if (strpos($allowedDomain, '*.') === 0) {
                $pattern = '/^' . str_replace('*.', '.*\.', preg_quote($allowedDomain, '/')) . '$/';
                if (preg_match($pattern, $domain)) {
                    return true;
                }
            }
        }

        return false;
    }

    public function isActive(): bool
    {
        return $this->is_active;
    }

    public function getSessionLifetimeInSeconds(): int
    {
        return $this->session_lifetime ?? 3600;
    }

    public function getSetting(string $key, $default = null)
    {
        return $this->settings[$key] ?? $default;
    }

    public function setSetting(string $key, $value): void
    {
        $settings = $this->settings ?? [];
        $settings[$key] = $value;
        $this->update(['settings' => $settings]);
    }
}
