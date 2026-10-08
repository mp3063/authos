<?php

namespace App\Filament\Concerns;

use App\Models\User;
use Filament\Facades\Filament;
use Illuminate\Database\Eloquent\Builder;

trait ScopesToOrganization
{
    protected static function scopeToOrganization(Builder $query, string $column = 'organization_id'): Builder
    {
        $organizationId = static::organizationIdToScope();

        if ($organizationId === false) {
            return $query;
        }

        if ($organizationId === null) {
            return $query->whereRaw('1 = 0');
        }

        return $query->where($query->getModel()->qualifyColumn($column), $organizationId);
    }

    protected static function scopeToOrganizationThrough(Builder $query, string $relation, string $column = 'organization_id'): Builder
    {
        $organizationId = static::organizationIdToScope();

        if ($organizationId === false) {
            return $query;
        }

        if ($organizationId === null) {
            return $query->whereRaw('1 = 0');
        }

        return $query->whereHas($relation, fn (Builder $related) => $related->where($related->getModel()->qualifyColumn($column), $organizationId));
    }

    protected static function scopeToOrganizationOrThrough(Builder $query, string $relation, string $column = 'organization_id'): Builder
    {
        $organizationId = static::organizationIdToScope();

        if ($organizationId === false) {
            return $query;
        }

        if ($organizationId === null) {
            return $query->whereRaw('1 = 0');
        }

        return $query->where(function (Builder $scoped) use ($organizationId, $relation, $column) {
            $scoped->where($scoped->getModel()->qualifyColumn($column), $organizationId)
                ->orWhere(function (Builder $fallback) use ($organizationId, $relation, $column) {
                    $fallback->whereNull($fallback->getModel()->qualifyColumn($column))
                        ->whereHas($relation, fn (Builder $related) => $related->where($related->getModel()->qualifyColumn($column), $organizationId));
                });
        });
    }

    private static function organizationIdToScope(): int|false|null
    {
        $user = Filament::auth()->user();

        if (! $user instanceof User) {
            return null;
        }

        if ($user->isSuperAdmin()) {
            return false;
        }

        return $user->organization_id;
    }
}
