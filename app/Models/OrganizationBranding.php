<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OrganizationBranding extends Model
{
    use HasFactory;

    protected $table = 'organization_branding';

    protected $fillable = [
        'organization_id',
        'logo_path',
        'login_background_path',
        'primary_color',
        'secondary_color',
        'custom_css',
        'email_templates',
        'settings',
    ];

    protected function casts(): array
    {
        return [
            'email_templates' => 'array',
            'settings' => 'array',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Get the logo URL
     */
    public function getLogoUrlAttribute(): ?string
    {
        return $this->logo_path ? asset('storage/'.$this->logo_path) : null;
    }

    /**
     * Get the background image URL
     */
    public function getBackgroundUrlAttribute(): ?string
    {
        return $this->login_background_path ? asset('storage/'.$this->login_background_path) : null;
    }

    /**
     * Sanitize custom CSS to prevent XSS
     */
    public function sanitizeCustomCss(string $css): string
    {
        // Remove script tags completely (including content)
        $css = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $css);

        // Remove potentially dangerous patterns
        $dangerous = [
            '/@import/i',
            '/javascript:/i',
            '/expression\(/i',
            '/behavior:/i',
            '/<script/i',
            '/onclick\s*=/i',
            '/onerror\s*=/i',
            '/onload\s*=/i',
            '/alert\s*\(/i',  // Remove alert() function calls
        ];

        return trim(preg_replace($dangerous, '', $css));
    }
}
