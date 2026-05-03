<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class UserConsent extends Model
{
    use HasFactory;

    public const TYPE_TERMS = 'terms';

    public const TYPE_PRIVACY = 'privacy';

    public const TYPE_MARKETING = 'marketing';

    public const TYPE_DATA_PROCESSING = 'data_processing';

    protected $fillable = [
        'user_id',
        'organization_id',
        'consent_type',
        'terms_version',
        'ip_address',
        'given_at',
        'withdrawn_at',
    ];

    protected function casts(): array
    {
        return [
            'given_at' => 'datetime',
            'withdrawn_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function isActive(): bool
    {
        return $this->given_at !== null && $this->withdrawn_at === null;
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNotNull('given_at')->whereNull('withdrawn_at');
    }

    public function scopeWithdrawn(Builder $query): Builder
    {
        return $query->whereNotNull('withdrawn_at');
    }

    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }
}
