<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Support\Str;
use App\Traits\BelongsToOrganization;

/**
 * @method static \Illuminate\Database\Eloquent\Builder where($column, $operator = null, $value = null, $boolean = 'and')
 * @method static \Illuminate\Database\Eloquent\Builder whereIn($column, $values, $boolean = 'and', $not = false)
 * @method static static create(array $attributes = [])
 * @method static static findOrFail($id, $columns = ['*'])
 * @method static \Illuminate\Database\Eloquent\Builder with($relations)
 * @method static \Illuminate\Database\Eloquent\Collection pluck($column, $key = null)
 * @property-read \Illuminate\Database\Eloquent\Collection|User[] $users
 * @property-read Organization $organization
 */
class Application extends Model
{
    use HasFactory, BelongsToOrganization;

    protected $fillable = [
        'organization_id',
        'name',
        'client_id',
        'client_secret',
        'redirect_uris',
        'allowed_origins',
        'allowed_grant_types',
        'webhook_url',
        'settings',
        'is_active',
    ];

    protected $casts = [
        'redirect_uris' => 'array',
        'allowed_origins' => 'array',
        'allowed_grant_types' => 'array',
        'settings' => 'array',
        'is_active' => 'boolean',
    ];

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($application) {
            if (empty($application->client_id)) {
                $application->client_id = Str::uuid();
            }
            if (empty($application->client_secret)) {
                $application->client_secret = Str::random(64);
            }
        });
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function users(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'user_applications')
            ->withPivot(['granted_by', 'granted_at', 'metadata', 'permissions', 'last_login_at', 'login_count'])
            ->withTimestamps();
    }

    public function ssoConfiguration(): HasOne
    {
        return $this->hasOne(\App\Models\SSOConfiguration::class);
    }

    public function ssoSessions(): HasMany
    {
        return $this->hasMany(\App\Models\SSOSession::class);
    }

    public function regenerateSecret(): void
    {
        $this->update(['client_secret' => Str::random(64)]);
    }

    public function hasSSOEnabled(): bool
    {
        return $this->ssoConfiguration && $this->ssoConfiguration->isActive();
    }
}
