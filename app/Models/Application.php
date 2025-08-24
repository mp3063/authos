<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Support\Str;

class Application extends Model
{
    use HasFactory;

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
            ->withPivot(['metadata', 'last_login_at', 'login_count'])
            ->withTimestamps();
    }

    public function regenerateSecret(): void
    {
        $this->update(['client_secret' => Str::random(64)]);
    }
}
