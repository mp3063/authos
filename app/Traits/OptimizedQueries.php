<?php

namespace App\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Cache;

trait OptimizedQueries
{
    /**
     * Scope to eager load common relationships.
     */
    public function scopeWithCommonRelations(Builder $query): Builder
    {
        $relations = $this->getCommonRelations();

        return $query->with($relations);
    }

    /**
     * Get common relationships for eager loading.
     */
    protected function getCommonRelations(): array
    {
        // Override in models to define common relationships
        return [];
    }

    /**
     * Cached query with automatic invalidation.
     */
    public static function cachedQuery(string $key, int $ttl, callable $callback)
    {
        return Cache::remember($key, $ttl, $callback);
    }

    /**
     * Scope for active records only.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where($this->getTable().'.is_active', true);
    }

    /**
     * Scope for organization-specific queries.
     */
    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where($this->getTable().'.organization_id', $organizationId);
    }

    /**
     * Efficiently count related records.
     */
    public function cachedCount(string $relation, int $ttl = 600): int
    {
        $cacheKey = sprintf(
            '%s:%s:%s:count',
            $this->getTable(),
            $this->getKey(),
            $relation
        );

        return Cache::remember($cacheKey, $ttl, function () use ($relation) {
            return $this->$relation()->count();
        });
    }

    /**
     * Get records with selective fields to reduce payload.
     */
    public function scopeSelectOptimized(Builder $query, array $fields = []): Builder
    {
        if (empty($fields)) {
            return $query;
        }

        // Always include the primary key
        if (! in_array($this->getKeyName(), $fields)) {
            $fields[] = $this->getKeyName();
        }

        return $query->select($fields);
    }

    /**
     * Chunk queries for better memory management.
     */
    public static function chunkOptimized(int $count, callable $callback): bool
    {
        return static::query()->chunk($count, $callback);
    }

    /**
     * Get paginated results with caching.
     */
    public static function cachedPaginate(string $cacheKey, int $perPage = 15, int $ttl = 300, array $with = [])
    {
        $page = request('page', 1);
        $fullCacheKey = "{$cacheKey}:page:{$page}:per_page:{$perPage}";

        return Cache::remember($fullCacheKey, $ttl, function () use ($perPage, $with) {
            $query = static::query();

            if (! empty($with)) {
                $query->with($with);
            }

            return $query->paginate($perPage);
        });
    }
}
