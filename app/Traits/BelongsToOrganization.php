<?php

namespace App\Traits;

use App\Models\Organization;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Builder;
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
            if (Auth::check() && !isset($model->organization_id)) {
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
     * Check if the model belongs to the specified organization
     */
    public function belongsToOrganization(int $organizationId): bool
    {
        return $this->organization_id === $organizationId;
    }

    /**
     * Check if the current user can access this model
     */
    public function canBeAccessedByUser($user = null): bool
    {
        $user = $user ?: Auth::user();
        
        if (!$user) {
            return false;
        }

        // Super admins can access everything
        if ($user->hasRole('super-admin')) {
            return true;
        }

        // Users can only access models from their organization
        return $this->organization_id === $user->organization_id;
    }

    /**
     * Scope to filter by organization
     */
    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }

    /**
     * Scope to filter by current user's organization
     */
    public function scopeForCurrentUserOrganization(Builder $query): Builder
    {
        if (Auth::check()) {
            return $query->where('organization_id', Auth::user()->organization_id);
        }
        
        return $query;
    }

    /**
     * Validate that the organization exists and is active
     */
    public function validateOrganization(): bool
    {
        if (!$this->organization_id) {
            return false;
        }

        $organization = Organization::find($this->organization_id);
        
        return $organization && $organization->is_active;
    }

    /**
     * Get all models accessible to the current user
     */
    public static function accessibleToCurrentUser(): Builder
    {
        $query = static::query();
        
        if (Auth::check() && !Auth::user()->hasRole('super-admin')) {
            $query->where('organization_id', Auth::user()->organization_id);
        }
        
        return $query;
    }
}