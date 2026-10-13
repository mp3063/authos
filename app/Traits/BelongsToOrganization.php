<?php

namespace App\Traits;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Auth;

trait BelongsToOrganization
{
    /**
     * Boot the BelongsToOrganization trait
     */
    protected static function bootBelongsToOrganization(): void
    {
        // REMOVED: Global scope that caused infinite loop with Auth::user()
        // The global scope was calling Auth::user() which loads User model
        // which triggers the global scope again, causing memory exhaustion

        // Automatically set organization_id when creating new records
        static::creating(function ($model) {
            if (Auth::check() && ! isset($model->organization_id)) {
                // Safe to use Auth::user() here as it's only during model creation
                $user = Auth::user();
                if ($user && $user->organization_id) {
                    $model->organization_id = $user->organization_id;
                }
            }
        });
    }

    /**
     * Define the organization relationship
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Scope to filter by organization
     */
    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }
}
